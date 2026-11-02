//! Data directory resolution and the optional `config.json` file.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::multiaddr::Protocol;
use serde::{Deserialize, Serialize};

const CONFIG_FILE: &str = "config.json";

/// `$XDG_DATA_HOME/dvpn`, usually `~/.local/share/dvpn`.
pub fn default_data_dir() -> anyhow::Result<PathBuf> {
    directories::ProjectDirs::from("", "", "dvpn")
        .map(|d| d.data_dir().to_path_buf())
        .context("could not determine the home directory; pass --data-dir")
}

/// Optional `<data-dir>/config.json`.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// Bootstrap peers as multiaddrs ending in `/p2p/<peer-id>`.
    pub bootstrap: Vec<String>,
    /// The service (`dvpn daemon`) starts lending when it starts, i.e. at boot.
    pub lend_at_boot: bool,
}

impl FileConfig {
    pub fn load(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join(CONFIG_FILE);
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("invalid {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Writes `<data-dir>/config.json` (owner-only, replaced atomically).
    pub fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
        let path = data_dir.join(CONFIG_FILE);
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        crate::identity::write_private(&path, &json).with_context(|| format!("writing {}", path.display()))
    }
}

/// Splits `/ip4/.../tcp/.../p2p/<id>` into the peer ID and its transport address.
pub fn split_peer_addr(addr: &Multiaddr) -> anyhow::Result<(PeerId, Multiaddr)> {
    let mut transport = addr.clone();
    match transport.pop() {
        Some(Protocol::P2p(peer_id)) => Ok((peer_id, transport)),
        _ => bail!("bootstrap address {addr} must end with /p2p/<peer-id>"),
    }
}
