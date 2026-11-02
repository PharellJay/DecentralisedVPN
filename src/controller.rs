//! What a user can do with dvpn while it runs (accept the lending terms, connect,
//! disconnect, turn off, choose exits), and the [`View`] of its state.
//!
//! Shared by the in-process dashboard (`sudo dvpn tui`) and the background service
//! (`dvpn daemon`), whose clients send [`Action`]s over the control socket.
//!
//! Lending starts with [`Action::Lend`] (lending on its own, without the VPN) or with the
//! first connect, and keeps running after a disconnect; [`Action::Stop`] turns both off.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, bail};
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::client::{self, ConnectOptions};
use crate::config::{self, FileConfig};
use crate::control::{self, CircuitReport, Phase, SharedState, StatusReport};
use crate::lend::{self, Lending};
use crate::logs::LogBuffer;
use crate::node::{NatState, Node};
use crate::select::{self, Availability, Measurement, Selection};

pub const PING_STEP: Duration = Duration::from_millis(10);
pub const MIN_PING: Duration = Duration::from_millis(1);
pub const MAX_PING: Duration = Duration::from_secs(60);
/// The limit offered when switching to max-ping mode for the first time.
pub const DEFAULT_PING_LIMIT: Duration = Duration::from_millis(100);
/// Log lines included in a [`View`].
const VIEW_LOG_LINES: usize = 200;

/// Everything that runs while lending: the node, the exit, and the state they share.
pub struct Session {
    pub node: Node,
    pub lending: Lending,
    pub state: SharedState,
    pub options: ConnectOptions,
    /// Serves `<data-dir>/control.sock` for this session, if it has its own.
    pub status_server: Option<JoinHandle<()>>,
}

type StartFuture = Pin<Box<dyn Future<Output = anyhow::Result<Session>> + Send>>;
/// Brings up a new [`Session`]; called again after [`Action::Stop`].
pub type StartFn = Box<dyn Fn() -> StartFuture + Send + Sync>;

/// A request from the user. Sent as JSON over the control socket, e.g.
/// `{"cmd":"act","action":"set_selection","max_ping_ms":80}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// The user accepts [`lend::LENDING_WARNING`]; needed once before anything starts.
    AcceptExitRisk,
    /// Start lending without connecting the VPN: volunteering this machine as an exit.
    Lend,
    /// Start lending if it isn't running, then connect the VPN.
    Connect,
    /// Disconnect the VPN; lending keeps running.
    Disconnect,
    /// Disconnect and stop lending.
    Stop,
    /// `None` for random selection. Takes effect at the next circuit.
    SetSelection { max_ping_ms: Option<u64> },
    /// Measure exits again (starts lending first if needed).
    Measure,
    /// Remember a bootstrap peer in `config.json`; used from the next start.
    AddBootstrap { addr: String },
    /// Whether the service starts lending when it starts (at boot). Saved in
    /// `config.json`; doesn't start or stop anything now.
    SetLendAtBoot { enabled: bool },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LendingView {
    pub ready: bool,
    pub published: bool,
    pub publicly_reachable: bool,
    pub relay_reservations: usize,
    pub sessions: usize,
    pub max_sessions: usize,
    pub rate_mbps: u64,
    pub wan: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VpnView {
    /// The client task is running (from connect until disconnect or an error).
    pub running: bool,
    pub phase: Phase,
    /// The kill switch is in place (see [`StatusReport::protected`]).
    pub protected: bool,
    pub warnings: Vec<String>,
    pub circuit: Option<CircuitReport>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub peer_id: String,
    /// The lending terms were accepted; until then nothing can be started.
    pub consent_given: bool,
    /// The service starts lending when it starts (see [`Action::SetLendAtBoot`]).
    pub lend_at_boot: bool,
    /// The node and the exit are running (lending is on, though maybe not ready yet).
    pub running: bool,
    /// Why lending stopped or couldn't start, if it did.
    pub error: Option<String>,
    pub nat: NatState,
    pub routing_peers: usize,
    pub lending: LendingView,
    pub vpn: VpnView,
    pub selection: Selection,
    /// The limit max-ping mode uses, remembered while in random mode.
    pub ping_limit_ms: u64,
    pub measuring: bool,
    /// From the last measurement, for the current limit.
    pub availability: Option<Availability>,
    /// Some test circuits may have gone through our own tunnel, so times read high.
    pub measured_while_connected: bool,
    pub logs: Vec<String>,
}

impl View {
    /// The circuit, while the VPN runs.
    pub fn circuit_if_connected(&self) -> Option<&CircuitReport> {
        self.vpn.circuit.as_ref().filter(|_| self.vpn.running)
    }

    /// The selection the "toggle mode" control switches to.
    pub fn toggled_selection(&self) -> Selection {
        match self.selection {
            Selection::Random => Selection::MaxPing(Duration::from_millis(self.ping_limit_ms)),
            Selection::MaxPing(_) => Selection::Random,
        }
    }

    /// The selection with the ping limit changed by `delta_ms`, or `None` in random mode.
    pub fn adjusted_selection(&self, delta_ms: i64) -> Option<Selection> {
        let Selection::MaxPing(limit) = self.selection else {
            return None;
        };
        let ms = (limit.as_millis() as i64).saturating_add(delta_ms);
        Some(Selection::MaxPing(clamp_limit(Duration::from_millis(ms.max(0) as u64))))
    }
}

fn clamp_limit(limit: Duration) -> Duration {
    limit.clamp(MIN_PING, MAX_PING)
}

pub fn selection_action(selection: Selection) -> Action {
    Action::SetSelection {
        max_ping_ms: match selection {
            Selection::Random => None,
            Selection::MaxPing(limit) => Some(limit.as_millis() as u64),
        },
    }
}

pub struct Controller {
    data_dir: PathBuf,
    peer_id: String,
    start: StartFn,
    session: Option<Session>,
    /// Why the last session stopped or failed to start.
    error: Option<String>,
    logs: LogBuffer,
    client: Option<JoinHandle<anyhow::Result<()>>>,
    client_error: Option<String>,
    measurement: Option<JoinHandle<Vec<Measurement>>>,
    measurements: Option<Vec<Measurement>>,
    /// Whether the VPN was running when the running/last measurement started.
    measuring_connected: bool,
    measured_while_connected: bool,
    selection: Selection,
    /// Kept when switching to random, so switching back restores it.
    ping_limit: Duration,
    lend_at_boot: bool,
}

impl Controller {
    pub fn new(data_dir: &Path, peer_id: String, selection: Selection, logs: LogBuffer, start: StartFn) -> Self {
        let ping_limit = match selection {
            Selection::MaxPing(limit) => limit,
            Selection::Random => DEFAULT_PING_LIMIT,
        };
        // An unreadable config.json also fails the first start, which reports it.
        let lend_at_boot = FileConfig::load(data_dir).is_ok_and(|c| c.lend_at_boot);
        Self {
            lend_at_boot,
            data_dir: data_dir.to_path_buf(),
            peer_id,
            start,
            session: None,
            error: None,
            logs,
            client: None,
            client_error: None,
            measurement: None,
            measurements: None,
            measuring_connected: false,
            measured_while_connected: false,
            selection,
            ping_limit,
        }
    }

    pub fn is_running(&self) -> bool {
        self.session.is_some()
    }

    pub fn consent_given(&self) -> bool {
        lend::consent_given(&self.data_dir)
    }

    /// Whether the service should start lending when it starts.
    pub fn lend_at_boot(&self) -> bool {
        self.lend_at_boot
    }

    pub async fn act(&mut self, action: Action) -> anyhow::Result<()> {
        match action {
            Action::AcceptExitRisk => {
                if !lend::consent_given(&self.data_dir) {
                    lend::record_consent(&self.data_dir)?;
                    info!("lending terms accepted");
                }
            }
            Action::Lend => self.start().await?,
            Action::Connect => self.connect().await?,
            Action::Disconnect => self.disconnect().await,
            Action::Stop => self.stop().await,
            Action::SetSelection { max_ping_ms } => {
                let selection = match max_ping_ms {
                    None => Selection::Random,
                    Some(ms) => Selection::MaxPing(clamp_limit(Duration::from_millis(ms))),
                };
                self.set_selection(selection);
            }
            Action::Measure => {
                self.start().await?;
                self.measure();
            }
            Action::AddBootstrap { addr } => self.add_bootstrap(&addr)?,
            Action::SetLendAtBoot { enabled } => self.set_lend_at_boot(enabled)?,
        }
        Ok(())
    }

    /// Brings up the node and lending, if they aren't running.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        if !lend::consent_given(&self.data_dir) {
            bail!("the lending terms haven't been accepted yet");
        }
        match (self.start)().await {
            Ok(session) => {
                *session.state.selection.lock().expect("state lock") = self.selection;
                self.session = Some(session);
                self.error = None;
                Ok(())
            }
            Err(e) => {
                self.error = Some(format!("{e:#}"));
                Err(e)
            }
        }
    }

    async fn connect(&mut self) -> anyhow::Result<()> {
        self.start().await?;
        if self.client.is_some() {
            return Ok(());
        }
        let session = self.session.as_ref().expect("started above");
        self.client_error = None;
        session.state.set_error(None);
        session.state.set_phase(Phase::Idle);
        self.client = Some(tokio::spawn(client::run(
            session.node.handle.clone(),
            session.options.clone(),
            session.state.clone(),
        )));
        Ok(())
    }

    /// Dropping the client restores routing and DNS; waits until it has.
    async fn disconnect(&mut self) {
        if let Some(task) = self.client.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(session) = &self.session {
            session.state.set_phase(Phase::Idle);
            *session.state.circuit.lock().expect("state lock") = None;
        }
    }

    /// The VPN first (restores routes), then lending (restores the firewall), then the node.
    pub async fn stop(&mut self) {
        self.disconnect().await;
        if let Some(task) = self.measurement.take() {
            task.abort();
        }
        if let Some(session) = self.session.take() {
            if let Some(server) = session.status_server {
                // Releases the socket, so a new start can bind it.
                server.abort();
                let _ = server.await;
            }
            drop(session.lending);
            let _ = session.node.handle.shutdown().await;
            // Waits for the listen ports to be released, so a new start can bind them.
            if !session.node.task.is_finished() {
                let _ = tokio::time::timeout(Duration::from_secs(5), session.node.task).await;
            }
        }
    }

    fn set_selection(&mut self, selection: Selection) {
        self.selection = selection;
        if let Selection::MaxPing(limit) = selection {
            self.ping_limit = limit;
        }
        if let Some(session) = &self.session {
            *session.state.selection.lock().expect("state lock") = selection;
        }
        if matches!(selection, Selection::MaxPing(_)) && self.measurements.is_none() {
            self.measure();
        }
    }

    fn measure(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        if self.measurement.is_some() {
            return;
        }
        let handle = session.node.handle.clone();
        self.measuring_connected = session.state.protected.load(Ordering::Relaxed);
        self.measurement = Some(tokio::spawn(async move {
            let (Ok(exits), Ok(relays)) = (handle.find_exits().await, handle.find_relays().await) else {
                return Vec::new();
            };
            select::measure_exits(&handle, exits, relays, &|_, _| Ok(())).await
        }));
    }

    fn add_bootstrap(&self, addr: &str) -> anyhow::Result<()> {
        let parsed: Multiaddr = addr.trim().parse().context("not a valid multiaddr")?;
        config::split_peer_addr(&parsed)?;
        let mut file = FileConfig::load(&self.data_dir)?;
        let addr = parsed.to_string();
        if !file.bootstrap.contains(&addr) {
            file.bootstrap.push(addr);
            file.save(&self.data_dir)?;
            info!("bootstrap peer saved; it is used from the next start");
        }
        Ok(())
    }

    fn set_lend_at_boot(&mut self, enabled: bool) -> anyhow::Result<()> {
        if enabled && !self.consent_given() {
            bail!("the lending terms haven't been accepted yet");
        }
        let mut file = FileConfig::load(&self.data_dir)?;
        if file.lend_at_boot != enabled {
            file.lend_at_boot = enabled;
            file.save(&self.data_dir)?;
        }
        self.lend_at_boot = enabled;
        info!("lending at boot is {}", if enabled { "on" } else { "off" });
        Ok(())
    }

    /// Collects finished background work. Call regularly (the dashboard does on every tick).
    pub async fn poll(&mut self) {
        if self.client.as_ref().is_some_and(JoinHandle::is_finished) {
            let task = self.client.take().expect("checked");
            self.client_error = match task.await {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(e) => Some(format!("client task failed: {e}")),
            };
            if let Some(session) = &self.session {
                session.state.set_phase(Phase::Idle);
            }
        }
        if self.measurement.as_ref().is_some_and(JoinHandle::is_finished) {
            let task = self.measurement.take().expect("checked");
            self.measurements = Some(task.await.unwrap_or_default());
            self.measured_while_connected = self.measuring_connected;
        }
        if self.session.as_ref().is_some_and(|s| s.node.task.is_finished()) {
            let session = self.session.as_mut().expect("checked");
            let error = match (&mut session.node.task).await {
                Ok(Ok(())) => "the node stopped".to_string(),
                Ok(Err(e)) => format!("the node stopped: {e:#}"),
                Err(e) => format!("the node stopped: {e}"),
            };
            warn!("{error}; lending and the VPN are off");
            self.stop().await;
            self.error = Some(error);
        }
    }

    pub async fn view(&self) -> anyhow::Result<View> {
        let mut logs = self.logs.lines();
        logs.drain(..logs.len().saturating_sub(VIEW_LOG_LINES));
        let availability = match (self.selection, &self.measurements) {
            (Selection::MaxPing(limit), Some(m)) => Some(select::availability(m, limit)),
            _ => None,
        };
        let mut view = View {
            peer_id: self.peer_id.clone(),
            consent_given: lend::consent_given(&self.data_dir),
            lend_at_boot: self.lend_at_boot,
            running: false,
            error: self.error.clone(),
            nat: NatState::Unknown,
            routing_peers: 0,
            lending: LendingView::default(),
            vpn: VpnView {
                last_error: self.client_error.clone(),
                ..VpnView::default()
            },
            selection: self.selection,
            ping_limit_ms: self.ping_limit.as_millis() as u64,
            measuring: self.measurement.is_some(),
            availability,
            measured_while_connected: self.measured_while_connected,
            logs,
        };
        let Some(session) = &self.session else {
            return Ok(view);
        };
        let handle = &session.node.handle;
        let status = handle.status().await.context("node stopped")?;
        let state = &session.state;
        let lending = session.lending.handle();
        view.running = true;
        view.nat = status.nat;
        view.routing_peers = handle.routing_peers().await.context("node stopped")?.len();
        view.lending = LendingView {
            ready: lending.ready(&status),
            published: status.exit_published,
            publicly_reachable: status.publicly_reachable || status.nat == NatState::Public,
            relay_reservations: status.relay_reservations,
            sessions: lending.active.load(Ordering::Relaxed),
            max_sessions: lending.max_sessions,
            rate_mbps: lending.rate_mbps,
            wan: lending.wan.clone(),
        };
        view.vpn = VpnView {
            running: self.client.is_some(),
            phase: *state.phase.lock().expect("state lock"),
            protected: state.protected.load(Ordering::Relaxed),
            warnings: state.warnings.lock().expect("state lock").clone(),
            circuit: state.circuit.lock().expect("state lock").clone(),
            last_error: self.client_error.clone().or_else(|| state.last_error.lock().expect("state lock").clone()),
        };
        Ok(view)
    }

    /// The node's status report (`dvpn status`), while lending runs.
    pub async fn status(&self) -> anyhow::Result<StatusReport> {
        let session = self.session.as_ref().context("dvpn is idle: not lending or connected")?;
        control::report(&session.node.handle, &session.state).await
    }
}
