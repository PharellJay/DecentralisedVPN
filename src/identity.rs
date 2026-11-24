//! Node identity: key generation, storage and permission checks.
//!
//! Servers (bootstrap peers, dedicated exits) keep a stable identity, since others find
//! them by it. Users' nodes get a new, [`Identity::ephemeral`] one for every session, so
//! the network can't recognise a computer across restarts and networks.
//!
//! A stable identity is one key in the data directory, `identity.key`: the Ed25519
//! libp2p keypair (the node ID).
//!
//! An exit's X25519 Noise key ([`ExitKeys`]) is never stored: it is made when the node
//! starts, replaced every day, and published in the exit record, which the node ID
//! signs. A key stolen from a running exit is useless a day later, and none can be
//! read from the disk.
//!
//! The directory and key files must be private to their owner (`0700` and `0600` on
//! Linux); anything looser is rejected.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use libp2p::identity::Keypair;
use zeroize::Zeroizing;

pub use crate::platform::files::write_private;
use crate::platform::files;

const NODE_KEY_FILE: &str = "identity.key";
/// Where earlier versions kept the exit's Noise key; deleted when found.
const OLD_EXIT_KEY_FILE: &str = "exit_static.key";
/// How long an exit uses one Noise key.
pub const EXIT_KEY_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a replaced key is still accepted: as long as records with it can be valid
/// ([`crate::records::RECORD_LIFETIME`]), plus a margin for clocks and slow lookups.
pub const EXIT_KEY_GRACE: Duration = Duration::from_secs(70 * 60);
pub const NOISE_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("an identity already exists in {0}")]
    AlreadyExists(PathBuf),
    #[error("no identity found in {0}; run `dvpn init` first")]
    NotFound(PathBuf),
    #[error("{path} has insecure permissions {mode:o}; group/other must have no access")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("key file {0} is corrupt")]
    Corrupt(PathBuf),
    #[error("key generation failed: {0}")]
    KeyGen(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// X25519 static keypair for the exit-side Noise handshake.
pub struct ExitStaticKey {
    pub private: Zeroizing<Vec<u8>>,
    pub public: [u8; 32],
}

impl ExitStaticKey {
    pub fn generate() -> Result<Self, IdentityError> {
        let params = NOISE_PARAMS.parse().map_err(|e: snow::Error| IdentityError::KeyGen(e.to_string()))?;
        let snow::Keypair { private, public } = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|e| IdentityError::KeyGen(e.to_string()))?;
        // Moved, not copied, so no unzeroed copy of the private key stays behind.
        let private = Zeroizing::new(private);
        let public = public
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::KeyGen("unexpected X25519 key length".into()))?;
        Ok(Self { private, public })
    }
}

/// An exit's Noise keys: the current one, published in its record, and the one it
/// replaced, accepted until records with it have expired.
pub struct ExitKeys {
    ring: Mutex<Ring>,
    lifetime: Duration,
    grace: Duration,
}

struct Ring {
    current: ExitStaticKey,
    since: Instant,
    /// The replaced key and when it was replaced.
    previous: Option<(ExitStaticKey, Instant)>,
}

impl ExitKeys {
    /// A fresh key, replaced every [`EXIT_KEY_LIFETIME`].
    pub fn new() -> Result<Self, IdentityError> {
        Self::with_lifetimes(EXIT_KEY_LIFETIME, EXIT_KEY_GRACE)
    }

    /// Each key is used for `lifetime`, then still accepted for `grace`.
    pub fn with_lifetimes(lifetime: Duration, grace: Duration) -> Result<Self, IdentityError> {
        Ok(Self {
            ring: Mutex::new(Ring {
                current: ExitStaticKey::generate()?,
                since: Instant::now(),
                previous: None,
            }),
            lifetime,
            grace,
        })
    }

    /// The key to publish.
    pub fn public(&self) -> [u8; 32] {
        self.ring.lock().expect("key lock").current.public
    }

    /// The private keys a client may be using, current first.
    pub fn candidates(&self) -> Vec<Zeroizing<Vec<u8>>> {
        let ring = self.ring.lock().expect("key lock");
        let previous = ring.previous.as_ref().filter(|(_, at)| at.elapsed() < self.grace);
        std::iter::once(&ring.current)
            .chain(previous.map(|(key, _)| key))
            .map(|key| key.private.clone())
            .collect()
    }

    /// Replaces the current key once it's older than its lifetime; `true` if it did
    /// (the record must be published again). A key older than the grace period goes.
    pub fn rotate_if_due(&self) -> bool {
        let mut ring = self.ring.lock().expect("key lock");
        if ring.previous.as_ref().is_some_and(|(_, at)| at.elapsed() >= self.grace) {
            ring.previous = None;
        }
        if ring.since.elapsed() < self.lifetime {
            return false;
        }
        let Ok(new) = ExitStaticKey::generate() else {
            return false;
        };
        let old = std::mem::replace(&mut ring.current, new);
        ring.previous = Some((old, Instant::now()));
        ring.since = Instant::now();
        true
    }
}

pub struct Identity {
    pub keypair: Keypair,
}

impl Identity {
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// A new identity that lives only in memory.
    pub fn ephemeral() -> Result<Self, IdentityError> {
        Ok(Self {
            keypair: Keypair::generate_ed25519(),
        })
    }

    /// Generates a fresh identity in `dir`. Refuses to overwrite an existing one.
    pub fn init(dir: &Path) -> Result<Self, IdentityError> {
        let node_path = dir.join(NODE_KEY_FILE);
        if node_path.exists() {
            return Err(IdentityError::AlreadyExists(dir.to_path_buf()));
        }
        ensure_data_dir(dir)?;

        let Self { keypair } = Self::ephemeral()?;
        let node_bytes = Zeroizing::new(
            keypair
                .to_protobuf_encoding()
                .map_err(|e| IdentityError::KeyGen(e.to_string()))?,
        );
        write_private(&node_path, &node_bytes)?;
        Ok(Self { keypair })
    }

    /// Loads the identity from `dir`, verifying permissions first.
    pub fn load(dir: &Path) -> Result<Self, IdentityError> {
        let node_path = dir.join(NODE_KEY_FILE);
        if !node_path.exists() {
            return Err(IdentityError::NotFound(dir.to_path_buf()));
        }
        check_private(dir)?;
        check_private(&node_path)?;

        let node_bytes = Zeroizing::new(fs::read(&node_path)?);
        let keypair = Keypair::from_protobuf_encoding(&node_bytes)
            .map_err(|_| IdentityError::Corrupt(node_path.clone()))?;
        // A long-lived secret that nothing uses any more.
        let _ = fs::remove_file(dir.join(OLD_EXIT_KEY_FILE));
        Ok(Self { keypair })
    }
}

/// Creates the data directory, private to this user, if needed, and checks it's private.
pub fn ensure_data_dir(dir: &Path) -> Result<(), IdentityError> {
    files::create_private_dir(dir)?;
    check_private(dir)
}

/// Rejects files or directories other users can access.
pub fn check_private(path: &Path) -> Result<(), IdentityError> {
    match files::loose_permissions(path)? {
        Some(mode) => Err(IdentityError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn init_creates_private_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dvpn");
        Identity::init(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(NODE_KEY_FILE)), 0o600);
        assert!(!dir.join(OLD_EXIT_KEY_FILE).exists(), "the exit key is never stored");
    }

    #[test]
    fn init_refuses_to_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dvpn");
        Identity::init(&dir).unwrap();
        assert!(matches!(Identity::init(&dir), Err(IdentityError::AlreadyExists(_))));
    }

    #[test]
    fn load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dvpn");
        let created = Identity::init(&dir).unwrap();
        let loaded = Identity::load(&dir).unwrap();
        assert_eq!(created.peer_id(), loaded.peer_id());
    }

    #[test]
    fn exit_keys_stored_by_earlier_versions_are_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dvpn");
        Identity::init(&dir).unwrap();
        write_private(&dir.join(OLD_EXIT_KEY_FILE), &[7; 64]).unwrap();
        Identity::load(&dir).unwrap();
        assert!(!dir.join(OLD_EXIT_KEY_FILE).exists());
    }

    #[test]
    fn exit_keys_rotate_and_the_old_one_is_accepted_for_a_while() {
        let keys = ExitKeys::with_lifetimes(Duration::from_secs(3600), Duration::from_secs(3600)).unwrap();
        assert!(!keys.rotate_if_due(), "a new key isn't replaced");
        assert_eq!(keys.candidates().len(), 1);

        let keys = ExitKeys::with_lifetimes(Duration::ZERO, Duration::from_secs(3600)).unwrap();
        let first = keys.public();
        let first_private = keys.candidates().remove(0);
        assert!(keys.rotate_if_due());
        assert_ne!(keys.public(), first, "a new key is published");
        let candidates = keys.candidates();
        assert_eq!(candidates.len(), 2, "the replaced key is still accepted");
        assert_ne!(*candidates[0], *first_private, "the current key comes first");
        assert_eq!(*candidates[1], *first_private);

        let keys = ExitKeys::with_lifetimes(Duration::ZERO, Duration::ZERO).unwrap();
        assert!(keys.rotate_if_due());
        assert_eq!(keys.candidates().len(), 1, "after the grace period only the current key");
    }

    #[test]
    fn load_rejects_readable_key() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dvpn");
        Identity::init(&dir).unwrap();
        fs::set_permissions(dir.join(NODE_KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Identity::load(&dir),
            Err(IdentityError::InsecurePermissions { .. })
        ));
    }

    #[test]
    fn load_rejects_open_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dvpn");
        Identity::init(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            Identity::load(&dir),
            Err(IdentityError::InsecurePermissions { .. })
        ));
    }

    #[test]
    fn ephemeral_identities_are_new_each_time() {
        let (a, b) = (Identity::ephemeral().unwrap(), Identity::ephemeral().unwrap());
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn load_without_init_fails() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(Identity::load(tmp.path()), Err(IdentityError::NotFound(_))));
    }
}
