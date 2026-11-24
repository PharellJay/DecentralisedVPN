//! The control socket: a Unix socket, and who is on the other end of a connection.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

pub type Listener = tokio::net::UnixListener;
pub type Stream = tokio::net::UnixStream;

const SOCKET_FILE: &str = "control.sock";
/// `sun_path` is 108 bytes on Linux, including the terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

/// The process on the other end of a control connection, as the kernel reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
}

pub async fn accept(listener: &Listener) -> io::Result<(Stream, Option<Peer>)> {
    let (stream, _) = listener.accept().await?;
    let peer = stream.peer_cred().ok().map(|cred| Peer {
        uid: cred.uid(),
        pid: cred.pid(),
    });
    Ok((stream, peer))
}

pub async fn connect(path: &Path) -> io::Result<Stream> {
    Stream::connect(path).await
}

/// Where `dvpn run` and `dvpn connect` serve status for `data_dir`: in it, or in the
/// private `$XDG_RUNTIME_DIR` when that path is too long for a Unix socket.
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

/// A socket only this user can connect to.
pub async fn bind_private(path: &Path) -> anyhow::Result<Listener> {
    bind(path, 0o600).await
}

/// A socket anyone can connect to; the server decides whom it answers.
pub async fn bind_public(path: &Path) -> anyhow::Result<Listener> {
    bind(path, 0o666).await
}

/// Binds a socket at `path` with `mode`, replacing a stale socket but never a live one.
async fn bind(path: &Path, mode: u32) -> anyhow::Result<Listener> {
    if path.exists() {
        if Stream::connect(path).await.is_ok() {
            bail!("another dvpn instance is already running ({} is in use)", path.display());
        }
        std::fs::remove_file(path).context("removing stale control socket")?;
    }
    let listener = Listener::bind(path).context("binding control socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

