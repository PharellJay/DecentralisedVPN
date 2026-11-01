//! Local status API over a Unix socket at `<data-dir>/control.sock`, or in the
//! private `$XDG_RUNTIME_DIR` when that path is too long for a Unix socket.
//!
//! Both directories are private to the user and the socket is 0600, so only the
//! owner can query it. World-writable locations like /tmp are never used.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::lend::LendingHandle;
use crate::node::NodeHandle;
use crate::select::{ProbeReport, Selection};

const SOCKET_FILE: &str = "control.sock";
/// `sun_path` is 108 bytes on Linux, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

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
    let path = socket_path(data_dir)?;
    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            bail!("another dvpn instance is already running with {}", data_dir.display());
        }
        std::fs::remove_file(&path).context("removing stale control socket")?;
    }
    let listener = UnixListener::bind(&path).context("binding control socket")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn serve(listener: UnixListener, handle: NodeHandle, state: SharedState) {
    while let Ok((mut stream, _)) = listener.accept().await {
        // A failed report (e.g. the node is shutting down) skips this request only.
        let Ok(report) = report(&handle, &state).await else {
            continue;
        };
        let mut json = serde_json::to_vec(&report).expect("serializable");
        json.push(b'\n');
        let _ = stream.write_all(&json).await;
    }
}

async fn report(handle: &NodeHandle, state: &SharedState) -> anyhow::Result<StatusReport> {
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

/// Client side of `dvpn status`.
pub async fn query(data_dir: &Path) -> anyhow::Result<StatusReport> {
    let path = socket_path(data_dir)?;
    let mut stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("no running dvpn node for {} (is `dvpn run` or `dvpn connect` running?)", data_dir.display()))?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}
