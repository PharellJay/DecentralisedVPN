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
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// Bootstrap peers as multiaddrs ending in `/p2p/<peer-id>`.
    pub bootstrap: Vec<String>,
    /// The service (`dvpn daemon`) starts lending when it starts, i.e. at boot.
    /// On unless the user turns it off; it still waits for the lending terms.
    pub lend_at_boot: bool,
    /// Find a first peer on the BitTorrent DHT, and announce there while lending
    /// (`crate::rendezvous`). On unless the user turns it off.
    pub rendezvous: bool,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            lend_at_boot: true,
            rendezvous: true,
        }
    }
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

/// How invite links start: `dvpn://join?peer=<multiaddr>&peer=<multiaddr>`.
pub const INVITE_PREFIX: &str = "dvpn://join?";
/// Peers in an invite: enough to get in, short enough to paste anywhere.
pub const MAX_INVITE_PEERS: usize = 4;

/// An invite link for `peers` (multiaddrs ending in `/p2p/<id>`), or `None` without any.
pub fn invite_link(peers: &[Multiaddr]) -> Option<String> {
    let peers: Vec<String> = peers.iter().take(MAX_INVITE_PEERS).map(|p| format!("peer={p}")).collect();
    (!peers.is_empty()).then(|| format!("{INVITE_PREFIX}{}", peers.join("&")))
}

/// The bootstrap peers in `text`: an invite link, or a single multiaddr. Each must end
/// in `/p2p/<id>`.
pub fn parse_peers(text: &str) -> anyhow::Result<Vec<Multiaddr>> {
    let text = text.trim();
    let Some(query) = text.strip_prefix(INVITE_PREFIX) else {
        let addr: Multiaddr = text
            .parse()
            .context("that isn't a peer address or invite link; an address looks like /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW…")?;
        split_peer_addr(&addr).map_err(|_| anyhow::anyhow!("the address must end with /p2p/ and the peer's ID"))?;
        return Ok(vec![addr]);
    };
    let mut peers = Vec::new();
    for pair in query.split('&') {
        let Some(value) = pair.strip_prefix("peer=") else {
            continue; // Fields a later version may add.
        };
        let addr: Multiaddr = percent_decode(value)
            .and_then(|v| v.parse().ok())
            .context("the invite link is damaged (an address in it doesn't parse)")?;
        split_peer_addr(&addr).context("the invite link is damaged")?;
        if !peers.contains(&addr) {
            peers.push(addr);
        }
    }
    if peers.is_empty() {
        bail!("the invite link has no peers in it");
    }
    peers.truncate(MAX_INVITE_PEERS);
    Ok(peers)
}

/// Undoes `%XX` escapes, which some apps add to links (e.g. `%2F` for `/`).
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Splits `/ip4/.../tcp/.../p2p/<id>` into the peer ID and its transport address.
pub fn split_peer_addr(addr: &Multiaddr) -> anyhow::Result<(PeerId, Multiaddr)> {
    let mut transport = addr.clone();
    match transport.pop() {
        Some(Protocol::P2p(peer_id)) => Ok((peer_id, transport)),
        _ => bail!("bootstrap address {addr} must end with /p2p/<peer-id>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
    const B: &str = "/ip6/2001:db8::1/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

    #[test]
    fn invite_links_round_trip() {
        let peers: Vec<Multiaddr> = [A, B].iter().map(|a| a.parse().unwrap()).collect();
        let link = invite_link(&peers).unwrap();
        assert_eq!(link, format!("dvpn://join?peer={A}&peer={B}"));
        assert_eq!(parse_peers(&link).unwrap(), peers);
        assert_eq!(invite_link(&[]), None);
    }

    #[test]
    fn peers_come_from_links_or_plain_addresses() {
        assert_eq!(parse_peers(&format!("  {A}\n")).unwrap(), [A.parse::<Multiaddr>().unwrap()]);
        let escaped = format!("dvpn://join?peer={}&future=1&peer={A}", A.replace('/', "%2F"));
        assert_eq!(parse_peers(&escaped).unwrap().len(), 1, "unescaped, unknown fields skipped, duplicates merged");
        assert!(parse_peers("/ip4/203.0.113.7/tcp/4001").is_err(), "no peer ID");
        assert!(parse_peers("dvpn://join?").is_err(), "no peers");
        assert!(parse_peers("dvpn://join?peer=/ip4/1.2.3.4/tcp/1").is_err(), "no peer ID in the link");
        assert!(parse_peers("dvpn://join?peer=%zz").is_err(), "bad escape");
        assert!(parse_peers("https://example.org").is_err());
    }

    #[test]
    fn lend_at_boot_is_on_unless_turned_off() {
        let dir = tempfile::tempdir().unwrap();
        assert!(FileConfig::load(dir.path()).unwrap().lend_at_boot, "no config.json");
        fs::write(dir.path().join(CONFIG_FILE), r#"{"bootstrap": []}"#).unwrap();
        assert!(FileConfig::load(dir.path()).unwrap().lend_at_boot, "field left out");
        fs::write(dir.path().join(CONFIG_FILE), r#"{"lend_at_boot": false}"#).unwrap();
        assert!(!FileConfig::load(dir.path()).unwrap().lend_at_boot, "turned off");
    }
}
