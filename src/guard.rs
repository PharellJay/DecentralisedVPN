//! Persistent entry-relay ("guard") choice; see docs/DESIGN.md §3.4.
//!
//! Reusing one entry relay for 30 days limits how often a client is exposed to a
//! freshly chosen, possibly malicious, entry.

use std::fs;
use std::path::Path;
use std::time::Duration;

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::identity::{check_private, write_private};
use crate::records::now_secs;

const GUARD_FILE: &str = "guard.json";
const GUARD_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Serialize, Deserialize)]
struct GuardFile {
    peer_id: String,
    chosen_at: u64,
}

/// The current guard, if one was chosen less than 30 days ago.
pub fn load(data_dir: &Path) -> Option<PeerId> {
    let path = data_dir.join(GUARD_FILE);
    check_private(&path).ok()?;
    let file: GuardFile = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
    let age = now_secs().saturating_sub(file.chosen_at);
    (age < GUARD_LIFETIME.as_secs()).then(|| file.peer_id.parse().ok()).flatten()
}

pub fn save(data_dir: &Path, peer: PeerId) -> anyhow::Result<()> {
    let file = GuardFile {
        peer_id: peer.to_string(),
        chosen_at: now_secs(),
    };
    write_private(&data_dir.join(GUARD_FILE), &serde_json::to_vec(&file)?)?;
    Ok(())
}

/// Forgets the guard after it stopped working.
pub fn clear(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(GUARD_FILE));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_clear() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), None);
        let peer = PeerId::random();
        save(dir.path(), peer).unwrap();
        assert_eq!(load(dir.path()), Some(peer));
        clear(dir.path());
        assert_eq!(load(dir.path()), None);
    }

    #[test]
    fn expired_guard_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let stale = GuardFile {
            peer_id: PeerId::random().to_string(),
            chosen_at: now_secs() - GUARD_LIFETIME.as_secs() - 1,
        };
        write_private(&dir.path().join(GUARD_FILE), &serde_json::to_vec(&stale).unwrap()).unwrap();
        assert_eq!(load(dir.path()), None);
    }
}
