//! Local control API over the platform's control socket ([`crate::platform::ipc`]).
//!
//! - `dvpn run` and `dvpn connect` serve status only, at `<data-dir>/control.sock` (or in
//!   the private `$XDG_RUNTIME_DIR` when that path is too long for a Unix socket). Both
//!   directories are private to the user and the socket is 0600, so only the owner can
//!   query it. World-writable locations like /tmp are never used.
//! - `dvpn daemon` also takes [`Action`]s, at [`crate::daemon::SERVICE_SOCKET`], and
//!   answers only users it allows (see `crate::daemon`).
//!
//! The protocol is one JSON [`Request`] per line, each answered by one JSON
//! [`Response`] line, e.g. `{"cmd":"status"}` or `{"cmd":"act","action":"connect"}`.
//! [`Request::Watch`] instead turns the connection into a feed of
//! [`Response::Update`]s, one whenever the service's state changes or new log lines
//! are written, until the client closes it.

use std::path::Path;
use std::pin::Pin;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::sync::watch;

use crate::controller::{Action, View};
use crate::datagram::Liveness;
use crate::lend::LendingHandle;
use crate::logs::LogBuffer;
use crate::node::NodeHandle;
pub use crate::platform::ipc::socket_path;
use crate::platform::ipc::{self, Listener, Peer, Stream};
use crate::select::{ProbeReport, Selection};

/// Longer request lines are refused (the connection is closed).
const MAX_REQUEST: u64 = 64 * 1024;
/// Log lines a new watcher gets first.
pub const WATCH_BACKLOG: u64 = 200;
/// Changes within this time go out as one update (log lines come in bursts).
const WATCH_COALESCE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// The node's [`StatusReport`].
    Status,
    /// The service's whole state, as shown by the app (`dvpn daemon` only).
    View,
    /// Something the user wants done (`dvpn daemon` only).
    Act(Action),
    /// Updates whenever the state changes, with new log lines if `logs` (`dvpn daemon`
    /// only). The connection takes no further requests.
    Watch {
        #[serde(default)]
        logs: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusReport>),
    View(Box<View>),
    /// The action was carried out.
    Done,
    /// For [`Request::Watch`]: what changed.
    Update(Box<Update>),
    Error(String),
    /// This connection's user may not control the service; the text says what to do.
    Denied(String),
}

/// What changed since the last update to a watcher. The first has the whole state and
/// the last [`WATCH_BACKLOG`] log lines.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Update {
    /// The state without its log lines, if it changed. Its `logs` are always empty.
    pub view: Option<View>,
    /// Log lines written since the last update.
    pub logs: Vec<String>,
}

/// What watchers are fed from: the latest state (kept current by the service while
/// anyone watches) and the log.
#[derive(Clone)]
pub struct Feed {
    pub views: Arc<watch::Sender<Option<Arc<View>>>>,
    pub logs: LogBuffer,
}

impl Feed {
    pub fn new(logs: LogBuffer) -> Self {
        Self {
            views: Arc::new(watch::Sender::new(None)),
            logs,
        }
    }

    /// Whether anyone watches, i.e. whether the state needs to be kept current.
    pub fn watched(&self) -> bool {
        self.views.receiver_count() > 0
    }

    /// Replaces the state (without its logs), telling watchers if it changed.
    pub fn publish(&self, mut view: View) {
        view.logs.clear();
        let json = serde_json::to_string(&view).ok();
        self.views.send_if_modified(|current| {
            let changed = current.as_ref().map(|c| serde_json::to_string(&**c).ok()) != Some(json.clone());
            if changed {
                *current = Some(Arc::new(view));
            }
            changed
        });
    }
}

/// The service refused this user (see [`Response::Denied`]).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PermissionDenied(pub String);

impl Response {
    pub fn from_result(result: anyhow::Result<()>) -> Self {
        match result {
            Ok(()) => Self::Done,
            Err(e) => Self::Error(format!("{e:#}")),
        }
    }
}

pub type Handler = Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;
/// Decides, once per connection, whether its peer may use the socket. May block (it can
/// ask polkit), so it runs off the async threads. `Err` holds the message for the peer.
pub type Authorize = Arc<dyn Fn(Option<Peer>) -> Result<(), String> + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitReport {
    pub relay: String,
    pub exit: String,
    /// The exit is another user lending while connected (used only when no dedicated exit fits).
    pub exit_is_user: bool,
    pub assigned_ip: String,
    /// Unix seconds.
    pub connected_since: u64,
    /// Packets currently go as datagrams (else over the circuit's stream).
    #[serde(default)]
    pub datagrams: bool,
    /// The exit's public IPv4 address from its record: where traffic appears to come
    /// from. `None` if its record only has relay addresses.
    #[serde(default)]
    pub exit_ip: Option<String>,
    /// Round trip to the exit through the circuit, once measured.
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    /// IP traffic through the VPN since connecting.
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub bytes_received: u64,
}

/// What went through the VPN since the user connected, and the circuit's latency.
#[derive(Default)]
pub struct Traffic {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    /// The last few round trips; their median is shown, so one keepalive answer that
    /// wasn't ours (datagram probes are keepalives too) doesn't skew it.
    rtts: Mutex<VecDeque<u64>>,
}

const RTT_SAMPLES: usize = 5;

impl Traffic {
    pub fn add_rtt(&self, rtt: std::time::Duration) {
        let mut rtts = self.rtts.lock().expect("traffic lock");
        rtts.push_back(rtt.as_millis() as u64);
        if rtts.len() > RTT_SAMPLES {
            rtts.pop_front();
        }
    }

    pub fn rtt_ms(&self) -> Option<u64> {
        let mut rtts: Vec<u64> = self.rtts.lock().expect("traffic lock").iter().copied().collect();
        rtts.sort_unstable();
        rtts.get(rtts.len() / 2).copied()
    }

    /// A new circuit: its latency is measured afresh.
    pub fn new_circuit(&self) {
        self.rtts.lock().expect("traffic lock").clear();
    }

    /// The user connected: counting starts over.
    pub fn reset(&self) {
        self.sent.store(0, Ordering::Relaxed);
        self.received.store(0, Ordering::Relaxed);
        self.new_circuit();
    }
}

/// Where `dvpn connect` is. Every phase but `Connected` blocks traffic once routes exist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    #[default]
    Idle,
    /// Our own exit isn't usable by others yet; no circuit is built until it is.
    WaitingForLending,
    Connecting,
    Connected,
    Reconnecting,
    /// Lending has been down too long; the circuit is closed and traffic blocked.
    Paused,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub peer_id: String,
    pub reachability: String,
    pub relay_reservations: usize,
    pub routing_peers: usize,
    pub hole_punches: usize,
    /// `dvpn connect`: the current circuit, or `None` while (re)connecting.
    pub circuit: Option<CircuitReport>,
    pub phase: Phase,
    /// The kill switch is in place: traffic either goes through the tunnel or nowhere.
    /// False until the first circuit is up, while traffic still goes out normally.
    pub protected: bool,
    /// Problems that weaken protection (e.g. DNS not going through the tunnel).
    pub warnings: Vec<String>,
    pub last_error: Option<String>,
    /// How exits are chosen: "random" or "max ping N ms".
    pub selection: String,
    /// The last max-ping search, if any.
    pub probe: Option<ProbeReport>,
    /// When lending: active exit sessions.
    pub exit_sessions: Option<usize>,
    pub exit_published: bool,
    /// When lending: whether others can use our exit right now.
    pub lending_ready: Option<bool>,
}

/// State shared between the running command and the status socket.
#[derive(Clone, Default)]
pub struct SharedState {
    pub circuit: Arc<Mutex<Option<CircuitReport>>>,
    pub phase: Arc<Mutex<Phase>>,
    pub last_error: Arc<Mutex<Option<String>>>,
    pub protected: Arc<AtomicBool>,
    pub warnings: Arc<Mutex<Vec<String>>>,
    pub lending: Option<LendingHandle>,
    /// Read before every circuit attempt, so it can be changed while running.
    pub selection: Arc<Mutex<Selection>>,
    pub probe: Arc<Mutex<Option<ProbeReport>>>,
    /// The current circuit's datagram path, if it has one.
    pub datagrams: Arc<Mutex<Option<Liveness>>>,
    pub traffic: Arc<Traffic>,
}

impl SharedState {
    /// The current circuit, with whether it uses datagrams right now.
    pub fn circuit_report(&self) -> Option<CircuitReport> {
        let mut report = self.circuit.lock().expect("state lock").clone()?;
        report.datagrams = self.datagrams.lock().expect("state lock").as_ref().is_some_and(Liveness::alive);
        report.rtt_ms = self.traffic.rtt_ms();
        report.bytes_sent = self.traffic.sent.load(Ordering::Relaxed);
        report.bytes_received = self.traffic.received.load(Ordering::Relaxed);
        Some(report)
    }

    pub fn set_phase(&self, phase: Phase) {
        *self.phase.lock().expect("state lock") = phase;
    }

    pub fn set_error(&self, error: Option<String>) {
        *self.last_error.lock().expect("state lock") = error;
    }
}

/// Binds the socket, refusing to start if another instance is already serving it.
pub async fn bind(data_dir: &Path) -> anyhow::Result<Listener> {
    ipc::bind_private(&socket_path(data_dir)?)
        .await
        .with_context(|| format!("starting dvpn with {}", data_dir.display()))
}

/// Serves status for `dvpn run` and `dvpn connect`, which take no actions.
pub async fn serve(listener: Listener, handle: NodeHandle, state: SharedState) {
    let handler: Handler = Arc::new(move |request| {
        let (handle, state) = (handle.clone(), state.clone());
        Box::pin(async move {
            match request {
                Request::Status => match report(&handle, &state).await {
                    Ok(report) => Response::Status(Box::new(report)),
                    Err(e) => Response::Error(format!("{e:#}")),
                },
                Request::View | Request::Act(_) | Request::Watch { .. } => Response::Error(
                    "this node was started from the command line; only the dvpn service takes actions".into(),
                ),
            }
        })
    });
    serve_with(listener, handler, None, None).await;
}

/// Answers requests on every connection with `handler`, until the listener fails. With
/// `authorize`, connections it refuses get [`Response::Denied`] to every request. With
/// `feed`, [`Request::Watch`] is served from it.
pub async fn serve_with(listener: Listener, handler: Handler, authorize: Option<Authorize>, feed: Option<Feed>) {
    while let Ok((stream, peer)) = ipc::accept(&listener).await {
        tokio::spawn(answer(stream, peer, handler.clone(), authorize.clone(), feed.clone()));
    }
}

async fn answer(
    stream: Stream,
    peer: Option<Peer>,
    handler: Handler,
    authorize: Option<Authorize>,
    feed: Option<Feed>,
) -> std::io::Result<()> {
    let verdict = match authorize {
        Some(authorize) => {
            tokio::task::spawn_blocking(move || authorize(peer))
                .await
                .unwrap_or_else(|_| Err("could not check permissions".into()))
        }
        None => Ok(()),
    };
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    loop {
        let mut line = String::new();
        if (&mut reader).take(MAX_REQUEST).read_line(&mut line).await? == 0 || !line.ends_with('\n') {
            return Ok(()); // Closed, or a request too long to be ours.
        }
        let response = match (&verdict, serde_json::from_str::<Request>(&line)) {
            (Err(denied), _) => Response::Denied(denied.clone()),
            (Ok(()), Ok(Request::Watch { logs })) => match &feed {
                Some(feed) => return watch_feed(reader, write, &handler, feed, logs).await,
                None => Response::Error("this node doesn't offer updates".into()),
            },
            (Ok(()), Ok(request)) => handler(request).await,
            (Ok(()), Err(e)) => Response::Error(format!("invalid request: {e}")),
        };
        send_line(&mut write, &response).await?;
    }
}

async fn send_line(write: &mut WriteHalf<Stream>, response: &Response) -> std::io::Result<()> {
    let mut json = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    json.push(b'\n');
    write.write_all(&json).await
}

/// Sends [`Response::Update`]s from `feed` until the client goes away.
async fn watch_feed(
    mut reader: BufReader<ReadHalf<Stream>>,
    mut write: WriteHalf<Stream>,
    handler: &Handler,
    feed: &Feed,
    logs: bool,
) -> std::io::Result<()> {
    let mut views = feed.views.subscribe();
    let mut written = feed.logs.subscribe();
    let mut cursor = feed.logs.written().saturating_sub(WATCH_BACKLOG);
    // The first update is asked for, since the feed may be stale while nobody watched.
    let mut first = match handler(Request::View).await {
        Response::View(mut view) => {
            view.logs.clear();
            Some(*view)
        }
        other => return send_line(&mut write, &other).await,
    };
    // Includes the state just fetched (the service publishes it), or anything newer.
    let mut view_changed = views.has_changed().unwrap_or(false);
    let mut scratch = [0; 256];
    loop {
        let mut update = Update {
            view: first.take(),
            logs: Vec::new(),
        };
        if std::mem::take(&mut view_changed) {
            update.view = views.borrow_and_update().as_deref().cloned();
        }
        if logs {
            written.mark_unchanged();
            update.logs = feed.logs.since(&mut cursor);
        }
        if update.view.is_some() || !update.logs.is_empty() {
            send_line(&mut write, &Response::Update(Box::new(update))).await?;
        }
        tokio::select! {
            changed = views.changed() => match changed {
                Ok(()) => view_changed = true,
                Err(_) => return Ok(()), // The service is stopping.
            },
            _ = written.changed(), if logs => {}
            // Nothing more is expected from the client; reading tells when it's gone.
            read = reader.read(&mut scratch) => if !matches!(read, Ok(1..)) {
                return Ok(());
            },
        }
        tokio::time::sleep(WATCH_COALESCE).await;
    }
}

pub(crate) async fn report(handle: &NodeHandle, state: &SharedState) -> anyhow::Result<StatusReport> {
    let status = handle.status().await?;
    Ok(StatusReport {
        peer_id: handle.peer_id().to_string(),
        reachability: format!("{:?}", status.nat),
        relay_reservations: status.relay_reservations,
        routing_peers: handle.routing_peers().await?.len(),
        hole_punches: status.hole_punches,
        circuit: state.circuit_report(),
        phase: *state.phase.lock().expect("state lock"),
        protected: state.protected.load(Ordering::Relaxed),
        warnings: state.warnings.lock().expect("state lock").clone(),
        last_error: state.last_error.lock().expect("state lock").clone(),
        selection: state.selection.lock().expect("state lock").to_string(),
        probe: state.probe.lock().expect("state lock").clone(),
        exit_sessions: state.lending.as_ref().map(|l| l.active.load(Ordering::Relaxed)),
        exit_published: status.exit_published,
        lending_ready: state.lending.as_ref().map(|l| l.ready(&status)),
    })
}

/// Client side of `dvpn status` for `dvpn run` and `dvpn connect`.
pub async fn query(data_dir: &Path) -> anyhow::Result<StatusReport> {
    let path = socket_path(data_dir)?;
    let stream = ipc::connect(&path)
        .await
        .with_context(|| format!("no running dvpn node for {} (is `dvpn run` or `dvpn connect` running?)", data_dir.display()))?;
    match Client::new(stream).send(&Request::Status).await? {
        Response::Status(report) => Ok(*report),
        Response::Error(e) => bail!("{e}"),
        other => bail!("unexpected answer: {other:?}"),
    }
}

/// One connection to a control socket; requests are answered in order.
pub struct Client {
    reader: BufReader<ReadHalf<Stream>>,
    writer: WriteHalf<Stream>,
}

impl Client {
    pub fn new(stream: Stream) -> Self {
        let (read, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read),
            writer,
        }
    }

    pub async fn connect(path: &Path) -> std::io::Result<Self> {
        Ok(Self::new(ipc::connect(path).await?))
    }

    pub async fn send(&mut self, request: &Request) -> anyhow::Result<Response> {
        let mut json = serde_json::to_vec(request)?;
        json.push(b'\n');
        self.writer.write_all(&json).await.context("sending to dvpn")?;
        let mut line = String::new();
        if self.reader.read_line(&mut line).await.context("reading from dvpn")? == 0 {
            bail!("dvpn closed the connection");
        }
        serde_json::from_str(&line).context("invalid answer from dvpn")
    }

    pub async fn view(&mut self) -> anyhow::Result<View> {
        match self.send(&Request::View).await? {
            Response::View(view) => Ok(*view),
            Response::Error(e) => bail!("{e}"),
            Response::Denied(help) => Err(PermissionDenied(help).into()),
            other => bail!("unexpected answer: {other:?}"),
        }
    }

    /// Turns this connection into a feed of updates (see [`Request::Watch`]).
    pub async fn watch(mut self, logs: bool) -> anyhow::Result<Watcher> {
        let mut json = serde_json::to_vec(&Request::Watch { logs })?;
        json.push(b'\n');
        self.writer.write_all(&json).await.context("sending to dvpn")?;
        Ok(Watcher { client: self })
    }

    pub async fn act(&mut self, action: Action) -> anyhow::Result<()> {
        match self.send(&Request::Act(action)).await? {
            Response::Done => Ok(()),
            Response::Error(e) => bail!("{e}"),
            Response::Denied(help) => Err(PermissionDenied(help).into()),
            other => bail!("unexpected answer: {other:?}"),
        }
    }
}

/// A connection that receives updates (see [`Client::watch`]).
pub struct Watcher {
    client: Client,
}

impl Watcher {
    /// The next update. The first has the whole state.
    pub async fn next(&mut self) -> anyhow::Result<Update> {
        let mut line = String::new();
        if self.client.reader.read_line(&mut line).await.context("reading from dvpn")? == 0 {
            bail!("dvpn closed the connection");
        }
        match serde_json::from_str(&line).context("invalid answer from dvpn")? {
            Response::Update(update) => Ok(*update),
            Response::Error(e) => bail!("{e}"),
            Response::Denied(help) => Err(PermissionDenied(help).into()),
            other => bail!("unexpected answer: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_is_the_median_of_recent_samples() {
        use std::time::Duration;
        let traffic = Traffic::default();
        assert_eq!(traffic.rtt_ms(), None);
        for ms in [40, 42, 1, 41, 300, 43] {
            traffic.add_rtt(Duration::from_millis(ms));
        }
        assert_eq!(traffic.rtt_ms(), Some(42), "outliers either way don't count");
        traffic.new_circuit();
        assert_eq!(traffic.rtt_ms(), None);
    }

    #[test]
    fn requests_are_flat_json_objects() {
        let set = Request::Act(Action::SetSelection { max_ping_ms: Some(80) });
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"{"cmd":"act","action":"set_selection","max_ping_ms":80}"#);
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), set);
        assert_eq!(serde_json::from_str::<Request>(r#"{"cmd":"act","action":"connect"}"#).unwrap(), Request::Act(Action::Connect));
        assert_eq!(serde_json::from_str::<Request>(r#"{"cmd":"status"}"#).unwrap(), Request::Status);
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"act","action":"rm -rf"}"#).is_err());
        assert_eq!(serde_json::from_str::<Request>(r#"{"cmd":"watch","logs":true}"#).unwrap(), Request::Watch { logs: true });
        assert_eq!(serde_json::from_str::<Request>(r#"{"cmd":"watch"}"#).unwrap(), Request::Watch { logs: false });
    }
}
