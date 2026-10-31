//! Local cache of known peers so later runs can rejoin without a bootstrap address.
//!
//! Stored as `<data-dir>/peers.json` with mode `0600`. It contains peer addresses,
//! so it never leaves the machine and can be disabled with `--no-peer-cache`.

use std::fs;
use std::path::Path;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::identity::{check_private, write_private};

const CACHE_FILE: &str = "peers.json";
pub const MAX_PEERS: usize = 64;
pub const MAX_ADDRS_PER_PEER: usize = 4;

#[derive(Default, Serialize, Deserialize)]
struct CacheFile {
    peers: Vec<CachedPeer>,
}

#[derive(Serialize, Deserialize)]
struct CachedPeer {
    peer_id: String,
    addrs: Vec<String>,
}

/// Returns cached peers. A missing file yields an empty list; malformed entries are skipped.
pub fn load(data_dir: &Path) -> anyhow::Result<Vec<(PeerId, Vec<Multiaddr>)>> {
    let path = data_dir.join(CACHE_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    check_private(&path)?;
    let file: CacheFile = serde_json::from_slice(&fs::read(&path)?).unwrap_or_default();
    Ok(file
        .peers
        .into_iter()
        .filter_map(|p| {
            let peer_id = p.peer_id.parse().ok()?;
            let addrs: Vec<Multiaddr> = p
                .addrs
                .iter()
                .filter_map(|a| a.parse().ok())
                .take(MAX_ADDRS_PER_PEER)
                .collect();
            (!addrs.is_empty()).then_some((peer_id, addrs))
        })
        .take(MAX_PEERS)
        .collect())
}

pub fn save(data_dir: &Path, peers: &[(PeerId, Vec<Multiaddr>)]) -> anyhow::Result<()> {
    let file = CacheFile {
        peers: peers
            .iter()
            .take(MAX_PEERS)
            .map(|(id, addrs)| CachedPeer {
                peer_id: id.to_string(),
                addrs: addrs.iter().take(MAX_ADDRS_PER_PEER).map(|a| a.to_string()).collect(),
            })
            .collect(),
    };
    write_private(&data_dir.join(CACHE_FILE), &serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn round_trip_with_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let peer = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        save(dir.path(), &[(peer, vec![addr.clone()])]).unwrap();

        let mode = fs::metadata(dir.path().join(CACHE_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(load(dir.path()).unwrap(), vec![(peer, vec![addr])]);
    }

    #[test]
    fn rejects_readable_cache() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &[]).unwrap();
        let path = dir.path().join(CACHE_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn missing_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_empty());
    }
}
