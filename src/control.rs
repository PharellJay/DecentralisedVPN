//! Local control API over a Unix socket.
//!
//! - `dvpn run` and `dvpn connect` serve status only, at `<data-dir>/control.sock` (or in
//!   the private `$XDG_RUNTIME_DIR` when that path is too long for a Unix socket). Both
//!   directories are private to the user and the socket is 0600, so only the owner can
//!   query it. World-writable locations like /tmp are never used.
//! - `dvpn daemon` also takes [`Action`]s, at [`crate::daemon::SERVICE_SOCKET`], which
//!   only root and the `dvpn` group can open (see `crate::daemon`).
//!
//! The protocol is one JSON [`Request`] per line, each answered by one JSON
//! [`Response`] line, e.g. `{"cmd":"status"}` or `{"cmd":"act","action":"connect"}`.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::controller::{Action, View};
use crate::lend::LendingHandle;
use crate::node::NodeHandle;
use crate::select::{ProbeReport, Selection};

const SOCKET_FILE: &str = "control.sock";
/// `sun_path` is 108 bytes on Linux, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 107;
/// Longer request lines are refused (the connection is closed).
const MAX_REQUEST: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// The node's [`StatusReport`].
    Status,
    /// The service's whole state, as shown by its dashboards (`dvpn daemon` only).
    View,
    /// Something the user wants done (`dvpn daemon` only).
    Act(Action),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusReport>),
    View(Box<View>),
    /// The action was carried out.
    Done,
    Error(String),
}

impl Response {
    pub fn from_result(result: anyhow::Result<()>) -> Self {
        match result {
            Ok(()) => Self::Done,
            Err(e) => Self::Error(format!("{e:#}")),
        }
    }
}

pub type Handler = Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitReport {
    pub relay: String,
    pub exit: String,
    /// The exit is another user lending while connected (used only when no dedicated exit fits).
    pub exit_is_user: bool,
    pub assigned_ip: String,
    /// Unix seconds.
    pub connected_since: u64,
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
}

impl SharedState {
    pub fn set_phase(&self, phase: Phase) {
        *self.phase.lock().expect("state lock") = phase;
    }

    pub fn set_error(&self, error: Option<String>) {
        *self.last_error.lock().expect("state lock") = error;
    }
}

pub fn socket_path(data_dir: &Path) -> anyhow::Result<PathBuf> {
    let in_data_dir = data_dir.join(SOCKET_FILE);
    if in_data_dir.as_os_str().len() <= MAX_SOCKET_PATH {
        return Ok(in_data_dir);
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let mut hasher = DefaultHasher::new();
        data_dir.hash(&mut hasher);
        let path = Path::new(&runtime).join(format!("dvpn-{:016x}.sock", hasher.finish()));
        if path.as_os_str().len() <= MAX_SOCKET_PATH {
            return Ok(path);
        }
    }
    bail!("--data-dir path is too long for the control socket; use a shorter one");
}

/// Binds the socket, refusing to start if another instance is already serving it.
pub async fn bind(data_dir: &Path) -> anyhow::Result<UnixListener> {
    bind_path(&socket_path(data_dir)?, 0o600)
        .await
        .with_context(|| format!("starting dvpn with {}", data_dir.display()))
}

/// Binds a socket at `path` with `mode`, replacing a stale socket but never a live one.
pub async fn bind_path(path: &Path, mode: u32) -> anyhow::Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).await.is_ok() {
            bail!("another dvpn instance is already running ({} is in use)", path.display());
        }
        std::fs::remove_file(path).context("removing stale control socket")?;
    }
    let listener = UnixListener::bind(path).context("binding control socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Serves status for `dvpn run` and `dvpn connect`, which take no actions.
pub async fn serve(listener: UnixListener, handle: NodeHandle, state: SharedState) {
    let handler: Handler = Arc::new(move |request| {
        let (handle, state) = (handle.clone(), state.clone());
        Box::pin(async move {
            match request {
                Request::Status => match report(&handle, &state).await {
                    Ok(report) => Response::Status(Box::new(report)),
                    Err(e) => Response::Error(format!("{e:#}")),
                },
                Request::View | Request::Act(_) => Response::Error(
                    "this node was started from the command line; only the dvpn service takes actions".into(),
                ),
            }
        })
    });
    serve_with(listener, handler).await;
}

/// Answers requests on every connection with `handler`, until the listener fails.
pub async fn serve_with(listener: UnixListener, handler: Handler) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(answer(stream, handler.clone()));
    }
}

async fn answer(stream: UnixStream, handler: Handler) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let mut line = String::new();
        if (&mut reader).take(MAX_REQUEST).read_line(&mut line).await? == 0 || !line.ends_with('\n') {
            return Ok(()); // Closed, or a request too long to be ours.
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handler(request).await,
            Err(e) => Response::Error(format!("invalid request: {e}")),
        };
        let mut json = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
        json.push(b'\n');
        write.write_all(&json).await?;
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
        circuit: state.circuit.lock().expect("state lock").clone(),
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
    let stream = UnixStream::connect(&path)
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
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl Client {
    pub fn new(stream: UnixStream) -> Self {
        let (read, writer) = stream.into_split();
        Self {
            reader: BufReader::new(read),
            writer,
        }
    }

    pub async fn connect(path: &Path) -> std::io::Result<Self> {
        Ok(Self::new(UnixStream::connect(path).await?))
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
            other => bail!("unexpected answer: {other:?}"),
        }
    }

    pub async fn act(&mut self, action: Action) -> anyhow::Result<()> {
        match self.send(&Request::Act(action)).await? {
            Response::Done => Ok(()),
            Response::Error(e) => bail!("{e}"),
            other => bail!("unexpected answer: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_flat_json_objects() {
        let set = Request::Act(Action::SetSelection { max_ping_ms: Some(80) });
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"{"cmd":"act","action":"set_selection","max_ping_ms":80}"#);
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), set);
        assert_eq!(serde_json::from_str::<Request>(r#"{"cmd":"act","action":"connect"}"#).unwrap(), Request::Act(Action::Connect));
        assert_eq!(serde_json::from_str::<Request>(r#"{"cmd":"status"}"#).unwrap(), Request::Status);
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"act","action":"rm -rf"}"#).is_err());
    }
}
