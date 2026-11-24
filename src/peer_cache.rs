//! Local cache of known peers so later runs can rejoin without a bootstrap address.
//!
//! Stored as `<data-dir>/peers.json` with mode `0600`. It contains peer addresses,
//! so it never leaves the machine and can be disabled with `--no-peer-cache`. Each save
//! replaces it with the peers known now; entries not refreshed for [`MAX_AGE`] (dvpn
//! wasn't running) are dropped, and the file is deleted once none are left.

use std::fs;
use std::path::Path;
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::identity::{check_private, write_private};
use crate::records::now_secs;

const CACHE_FILE: &str = "peers.json";
pub const MAX_PEERS: usize = 64;
pub const MAX_ADDRS_PER_PEER: usize = 4;
/// How long a cached peer is kept without being seen again.
pub const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Default, Serialize, Deserialize)]
struct CacheFile {
    peers: Vec<CachedPeer>,
}

#[derive(Serialize, Deserialize)]
struct CachedPeer {
    peer_id: String,
    addrs: Vec<String>,
    /// Unix seconds when it was last known. Entries from before this field count as
    /// seen when first loaded, so upgrading doesn't empty the cache.
    #[serde(default = "now_secs")]
    seen: u64,
}

/// Returns cached peers. A missing file yields an empty list; malformed entries are skipped.
pub fn load(data_dir: &Path) -> anyhow::Result<Vec<(PeerId, Vec<Multiaddr>)>> {
    let path = data_dir.join(CACHE_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    check_private(&path)?;
    let file: CacheFile = serde_json::from_slice(&fs::read(&path)?).unwrap_or_default();
    let now = now_secs();
    let fresh: Vec<CachedPeer> =
        file.peers.into_iter().filter(|p| now.saturating_sub(p.seen) < MAX_AGE.as_secs()).collect();
    if fresh.is_empty() {
        let _ = fs::remove_file(&path);
    }
    Ok(fresh
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
                seen: now_secs(),
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
    fn old_entries_expire_and_the_file_goes_with_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CACHE_FILE);
        let old = now_secs() - MAX_AGE.as_secs() - 1;
        let recent = now_secs() - 3600;
        let json = format!(
            r#"{{"peers":[{{"peer_id":"{}","addrs":["/ip4/192.0.2.1/tcp/4001"],"seen":{old}}},{{"peer_id":"{}","addrs":["/ip4/192.0.2.2/tcp/4001"],"seen":{recent}}}]}}"#,
            PeerId::random(),
            PeerId::random()
        );
        write_private(&path, json.as_bytes()).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1, "only the recent peer is kept");
        assert_eq!(loaded[0].1[0].to_string(), "/ip4/192.0.2.2/tcp/4001");

        let json = format!(r#"{{"peers":[{{"peer_id":"{}","addrs":["/ip4/192.0.2.1/tcp/4001"],"seen":{old}}}]}}"#, PeerId::random());
        write_private(&path, json.as_bytes()).unwrap();
        assert!(load(dir.path()).unwrap().is_empty());
        assert!(!path.exists(), "nothing left: the file is deleted");
    }

    #[test]
    fn entries_from_before_timestamps_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let json = format!(r#"{{"peers":[{{"peer_id":"{}","addrs":["/ip4/192.0.2.1/tcp/4001"]}}]}}"#, PeerId::random());
        write_private(&dir.path().join(CACHE_FILE), json.as_bytes()).unwrap();
        assert_eq!(load(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn missing_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_empty());
    }
}
