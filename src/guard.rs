//! Persistent entry-relay ("guard") choice; see docs/DESIGN.md §3.4.
//!
//! Reusing one entry relay for 30 days limits how often a client is exposed to a
//! freshly chosen, possibly malicious, entry. A guard that keeps failing is replaced,
//! so a relay that went offline can't keep the client from connecting.

use std::fs;
use std::path::Path;
use std::time::Duration;

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::identity::{check_private, write_private};
use crate::records::now_secs;

const GUARD_FILE: &str = "guard.json";
const GUARD_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Consecutive failures (unreachable, or no usable address) after which a guard is
/// replaced. A few, so one flaky moment doesn't hand the client to a fresh entry.
pub const MAX_GUARD_FAILURES: u32 = 3;

#[derive(Serialize, Deserialize)]
struct GuardFile {
    peer_id: String,
    chosen_at: u64,
    #[serde(default)]
    failures: u32,
}

fn read(data_dir: &Path) -> Option<GuardFile> {
    let path = data_dir.join(GUARD_FILE);
    check_private(&path).ok()?;
    let file: GuardFile = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
    let age = now_secs().saturating_sub(file.chosen_at);
    if age >= GUARD_LIFETIME.as_secs() {
        // It says which relay this computer used; no reason to keep that.
        let _ = fs::remove_file(&path);
        return None;
    }
    Some(file)
}

fn write(data_dir: &Path, file: &GuardFile) -> anyhow::Result<()> {
    write_private(&data_dir.join(GUARD_FILE), &serde_json::to_vec(file)?)?;
    Ok(())
}

/// The current guard, if one was chosen less than 30 days ago.
pub fn load(data_dir: &Path) -> Option<PeerId> {
    read(data_dir)?.peer_id.parse().ok()
}

pub fn save(data_dir: &Path, peer: PeerId) -> anyhow::Result<()> {
    write(
        data_dir,
        &GuardFile {
            peer_id: peer.to_string(),
            chosen_at: now_secs(),
            failures: 0,
        },
    )
}

/// The guard worked: its failure count starts over.
pub fn record_success(data_dir: &Path) {
    if let Some(mut file) = read(data_dir)
        && file.failures > 0
    {
        file.failures = 0;
        let _ = write(data_dir, &file);
    }
}

/// The guard couldn't be used. Returns true if that was one failure too many and it
/// was forgotten.
pub fn record_failure(data_dir: &Path) -> bool {
    let Some(mut file) = read(data_dir) else {
        return false;
    };
    file.failures += 1;
    if file.failures >= MAX_GUARD_FAILURES {
        clear(data_dir);
        return true;
    }
    let _ = write(data_dir, &file);
    false
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
    fn a_guard_that_keeps_failing_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let peer = PeerId::random();
        save(dir.path(), peer).unwrap();
        assert!(!record_failure(dir.path()));
        record_success(dir.path());
        for _ in 1..MAX_GUARD_FAILURES {
            assert!(!record_failure(dir.path()));
            assert_eq!(load(dir.path()), Some(peer), "a few failures are tolerated");
        }
        assert!(record_failure(dir.path()));
        assert_eq!(load(dir.path()), None);
    }

    #[test]
    fn expired_guard_is_ignored_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let stale = GuardFile {
            peer_id: PeerId::random().to_string(),
            chosen_at: now_secs() - GUARD_LIFETIME.as_secs() - 1,
            failures: 0,
        };
        write_private(&dir.path().join(GUARD_FILE), &serde_json::to_vec(&stale).unwrap()).unwrap();
        assert_eq!(load(dir.path()), None);
        assert!(!dir.path().join(GUARD_FILE).exists(), "and deleted");
    }
}
