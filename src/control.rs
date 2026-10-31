//! Local status API over a Unix socket at `<data-dir>/control.sock`, or in the
//! private `$XDG_RUNTIME_DIR` when that path is too long for a Unix socket.
//!
//! Both directories are private to the user and the socket is 0600, so only the
//! owner can query it. World-writable locations like /tmp are never used.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::node::NodeHandle;

const SOCKET_FILE: &str = "control.sock";
/// `sun_path` is 108 bytes on Linux, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitReport {
    pub relay: String,
    pub exit: String,
    pub assigned_ip: String,
    /// Unix seconds.
    pub connected_since: u64,
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
    /// `dvpn run --exit`: active exit sessions.
    pub exit_sessions: Option<usize>,
}

/// State shared between the running command and the status socket.
#[derive(Clone, Default)]
pub struct SharedState {
    pub circuit: Arc<Mutex<Option<CircuitReport>>>,
    pub exit_sessions: Option<Arc<AtomicUsize>>,
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
        let report = match report(&handle, &state).await {
            Ok(report) => report,
            Err(_) => return,
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
        exit_sessions: state.exit_sessions.as_ref().map(|n| n.load(Ordering::Relaxed)),
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
