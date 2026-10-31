//! Node identity: key generation, storage and permission checks.
//!
//! Two keys live in the data directory:
//! - `identity.key`: Ed25519 libp2p keypair (the node ID).
//! - `exit_static.key`: X25519 Noise static keypair, used only when acting as an exit.
//!
//! The directory must be `0700` and key files `0600`; anything looser is rejected.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use libp2p::PeerId;
use libp2p::identity::Keypair;
use zeroize::Zeroizing;

const NODE_KEY_FILE: &str = "identity.key";
const EXIT_KEY_FILE: &str = "exit_static.key";
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

pub struct Identity {
    pub keypair: Keypair,
    pub exit_static: ExitStaticKey,
}

impl Identity {
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// Generates a fresh identity in `dir`. Refuses to overwrite an existing one.
    pub fn init(dir: &Path) -> Result<Self, IdentityError> {
        let node_path = dir.join(NODE_KEY_FILE);
        if node_path.exists() {
            return Err(IdentityError::AlreadyExists(dir.to_path_buf()));
        }
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        check_private(dir)?;

        let keypair = Keypair::generate_ed25519();
        let node_bytes = Zeroizing::new(
            keypair
                .to_protobuf_encoding()
                .map_err(|e| IdentityError::KeyGen(e.to_string()))?,
        );

        let params = NOISE_PARAMS.parse().map_err(|e: snow::Error| IdentityError::KeyGen(e.to_string()))?;
        let noise = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|e| IdentityError::KeyGen(e.to_string()))?;
        let private = Zeroizing::new(noise.private.clone());
        let public: [u8; 32] = noise
            .public
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::KeyGen("unexpected X25519 key length".into()))?;
        let mut exit_bytes = Zeroizing::new(Vec::with_capacity(64));
        exit_bytes.extend_from_slice(&private);
        exit_bytes.extend_from_slice(&public);

        // The node key is written last: its presence marks a completed init.
        write_private(&dir.join(EXIT_KEY_FILE), &exit_bytes)?;
        write_private(&node_path, &node_bytes)?;

        Ok(Self {
            keypair,
            exit_static: ExitStaticKey { private, public },
        })
    }

    /// Loads the identity from `dir`, verifying permissions first.
    pub fn load(dir: &Path) -> Result<Self, IdentityError> {
        let node_path = dir.join(NODE_KEY_FILE);
        let exit_path = dir.join(EXIT_KEY_FILE);
        if !node_path.exists() {
            return Err(IdentityError::NotFound(dir.to_path_buf()));
        }
        check_private(dir)?;
        check_private(&node_path)?;
        check_private(&exit_path)?;

        let node_bytes = Zeroizing::new(fs::read(&node_path)?);
        let keypair = Keypair::from_protobuf_encoding(&node_bytes)
            .map_err(|_| IdentityError::Corrupt(node_path.clone()))?;

        let exit_bytes = Zeroizing::new(fs::read(&exit_path)?);
        if exit_bytes.len() != 64 {
            return Err(IdentityError::Corrupt(exit_path));
        }
        let private = Zeroizing::new(exit_bytes[..32].to_vec());
        let public: [u8; 32] = exit_bytes[32..].try_into().expect("length checked");

        Ok(Self {
            keypair,
            exit_static: ExitStaticKey { private, public },
        })
    }
}

/// Rejects files or directories accessible by group or other.
pub fn check_private(path: &Path) -> Result<(), IdentityError> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Writes `bytes` to `path` with mode `0600`, atomically via a temp file + rename.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    // A pre-existing temp file keeps its old mode, so enforce it explicitly.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
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
        assert_eq!(mode(&dir.join(EXIT_KEY_FILE)), 0o600);
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
        assert_eq!(created.exit_static.public, loaded.exit_static.public);
        assert_eq!(*created.exit_static.private, *loaded.exit_static.private);
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
    fn load_without_init_fails() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(Identity::load(tmp.path()), Err(IdentityError::NotFound(_))));
    }
}
