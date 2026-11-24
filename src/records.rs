//! Signed records published in the DHT.
//!
//! An exit publishes an [`ExitRecord`] wrapped in a libp2p `SignedEnvelope`, signed
//! with its node key, under `/dvpn/exit-record/v1/<peer-id>`. Exits and relays also
//! announce themselves as providers of [`exit_provider_key`] / [`relay_provider_key`].
//!
//! Those provider keys are split into [`PROVIDER_SHARDS`] shards, each node announcing
//! itself in the one its peer ID falls into, and lookups ask all shards. A DHT node
//! keeps only a limited number of providers per key and ignores newcomers once full,
//! so with a single key whoever got there first (e.g. an attacker's few dozen nodes)
//! would be all that anyone could find, and the network couldn't grow past that.
//!
//! Every node validates records before storing them, so nobody can overwrite another
//! exit's record, replay a stale one, or use the DHT as general-purpose storage.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::core::SignedEnvelope;
use libp2p::identity::Keypair;
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

const EXIT_PROVIDER_PREFIX: &str = "/dvpn/exit/v2/";
const RELAY_PROVIDER_PREFIX: &str = "/dvpn/relay/v2/";
/// Provider-key shards; see the module docs.
pub const PROVIDER_SHARDS: u8 = 8;
/// Providers a DHT node keeps per key (libp2p's default is 20).
pub const MAX_PROVIDERS_PER_KEY: usize = 64;
const EXIT_RECORD_PREFIX: &str = "/dvpn/exit-record/v1/";
const DOMAIN: &str = "dvpn-exit-record";
const PAYLOAD_TYPE: &[u8] = b"/dvpn/exit-record/2";

pub const RECORD_LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);
const MAX_RECORD_SIZE: usize = 4096;
pub const MAX_RECORD_ADDRS: usize = 8;
const MAX_BLOCKED_PORTS: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("record too large")]
    TooLarge,
    #[error("malformed record")]
    Malformed,
    #[error("invalid signature")]
    BadSignature,
    #[error("signer does not match the record's peer")]
    WrongSigner,
    #[error("record key does not match the record's peer")]
    WrongKey,
    #[error("record expired")]
    Expired,
    #[error("record expiry too far in the future")]
    TooFarInFuture,
}

/// What kind of exit a node says it is. Self-declared, so a node can lie; clients use
/// it only to prefer dedicated exits (docs/DESIGN.md §3.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitKind {
    /// `dvpn run --exit`: lends without using the VPN.
    Dedicated,
    /// A user's machine (`dvpn connect` or the service), lending whether it is
    /// connected or lends on its own. Used only when no dedicated exit fits.
    User,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitRecord {
    pub peer_id: PeerId,
    /// X25519 static key for the Noise_NK handshake with this exit.
    pub noise_static: [u8; 32],
    pub addrs: Vec<Multiaddr>,
    /// Exit policy summary: TCP destination ports this exit refuses.
    pub blocked_tcp_ports: Vec<u16>,
    pub kind: ExitKind,
    /// Unix seconds.
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    peer_id: Vec<u8>,
    noise_static: [u8; 32],
    addrs: Vec<Vec<u8>>,
    blocked_tcp_ports: Vec<u16>,
    kind: ExitKind,
    expires_at: u64,
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn exit_record_key(peer: &PeerId) -> RecordKey {
    RecordKey::new(&format!("{EXIT_RECORD_PREFIX}{peer}"))
}

/// The shard a peer announces itself in.
pub fn shard_of(peer: &PeerId) -> u8 {
    // The last byte of an Ed25519 peer ID is part of the public key: uniform.
    peer.to_bytes().last().copied().unwrap_or(0) % PROVIDER_SHARDS
}

pub fn exit_provider_key(shard: u8) -> RecordKey {
    RecordKey::new(&format!("{EXIT_PROVIDER_PREFIX}{shard}"))
}

pub fn relay_provider_key(shard: u8) -> RecordKey {
    RecordKey::new(&format!("{RELAY_PROVIDER_PREFIX}{shard}"))
}

/// Only our own provider namespaces are stored for other peers, and only in the shard
/// the provider belongs to (so nobody can crowd every shard with the same nodes).
pub fn is_known_provider_key(record: &ProviderRecord) -> bool {
    let shard = shard_of(&record.provider);
    record.key == exit_provider_key(shard) || record.key == relay_provider_key(shard)
}

impl ExitRecord {
    /// Signs the record with the exit's node key and wraps it in a DHT record.
    pub fn sign(&self, keypair: &Keypair) -> anyhow::Result<Record> {
        let payload = Payload {
            peer_id: self.peer_id.to_bytes(),
            noise_static: self.noise_static,
            addrs: self.addrs.iter().take(MAX_RECORD_ADDRS).map(|a| a.to_vec()).collect(),
            blocked_tcp_ports: self.blocked_tcp_ports.iter().take(MAX_BLOCKED_PORTS).copied().collect(),
            kind: self.kind,
            expires_at: self.expires_at,
        };
        let envelope = SignedEnvelope::new(
            keypair,
            DOMAIN.to_string(),
            PAYLOAD_TYPE.to_vec(),
            postcard::to_stdvec(&payload)?,
        )?;
        Ok(Record::new(exit_record_key(&self.peer_id), envelope.into_protobuf_encoding()))
    }

    /// Verifies signature, key binding and expiry against the current time.
    pub fn verify(record: &Record) -> Result<Self, RecordError> {
        Self::verify_at(record, now_secs())
    }

    pub fn verify_at(record: &Record, now: u64) -> Result<Self, RecordError> {
        if record.value.len() > MAX_RECORD_SIZE {
            return Err(RecordError::TooLarge);
        }
        let envelope = SignedEnvelope::from_protobuf_encoding(&record.value).map_err(|_| RecordError::Malformed)?;
        let (bytes, signer) = envelope
            .payload_and_signing_key(DOMAIN.to_string(), PAYLOAD_TYPE)
            .map_err(|_| RecordError::BadSignature)?;
        let payload: Payload = postcard::from_bytes(bytes).map_err(|_| RecordError::Malformed)?;
        let peer_id = PeerId::from_bytes(&payload.peer_id).map_err(|_| RecordError::Malformed)?;

        if signer.to_peer_id() != peer_id {
            return Err(RecordError::WrongSigner);
        }
        if record.key != exit_record_key(&peer_id) {
            return Err(RecordError::WrongKey);
        }
        if payload.expires_at <= now {
            return Err(RecordError::Expired);
        }
        if payload.expires_at > now + (RECORD_LIFETIME + MAX_CLOCK_SKEW).as_secs() {
            return Err(RecordError::TooFarInFuture);
        }
        if payload.addrs.len() > MAX_RECORD_ADDRS || payload.blocked_tcp_ports.len() > MAX_BLOCKED_PORTS {
            return Err(RecordError::Malformed);
        }
        let addrs = payload
            .addrs
            .into_iter()
            .map(Multiaddr::try_from)
            .collect::<Result<_, _>>()
            .map_err(|_| RecordError::Malformed)?;

        Ok(Self {
            peer_id,
            noise_static: payload.noise_static,
            addrs,
            blocked_tcp_ports: payload.blocked_tcp_ports,
            kind: payload.kind,
            expires_at: payload.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_for(keypair: &Keypair, expires_at: u64) -> ExitRecord {
        ExitRecord {
            peer_id: keypair.public().to_peer_id(),
            noise_static: [7; 32],
            addrs: vec!["/ip4/203.0.114.9/tcp/4001".parse().unwrap()],
            blocked_tcp_ports: vec![25],
            kind: ExitKind::Dedicated,
            expires_at,
        }
    }

    #[test]
    fn providers_are_stored_only_in_their_own_shard() {
        let peer = PeerId::random();
        let own = shard_of(&peer);
        let other = (own + 1) % PROVIDER_SHARDS;
        let record = |key| ProviderRecord::new(key, peer, vec![]);
        assert!(is_known_provider_key(&record(exit_provider_key(own))));
        assert!(is_known_provider_key(&record(relay_provider_key(own))));
        assert!(!is_known_provider_key(&record(exit_provider_key(other))), "crowding another shard");
        assert!(!is_known_provider_key(&record(RecordKey::new(&"/something/else"))));
        // Shards are spread out.
        let shards: std::collections::HashSet<u8> = (0..200).map(|_| shard_of(&PeerId::random())).collect();
        assert_eq!(shards.len(), PROVIDER_SHARDS as usize);
    }

    #[test]
    fn valid_record_round_trips() {
        let key = Keypair::generate_ed25519();
        let now = 1_000_000;
        let original = record_for(&key, now + 3600);
        let signed = original.sign(&key).unwrap();
        assert_eq!(ExitRecord::verify_at(&signed, now).unwrap(), original);
    }

    #[test]
    fn rejects_record_signed_by_someone_else() {
        let exit = Keypair::generate_ed25519();
        let attacker = Keypair::generate_ed25519();
        let now = 1_000_000;
        // Attacker claims to be `exit` but can only sign with its own key.
        let forged = record_for(&exit, now + 3600).sign(&attacker).unwrap();
        assert_eq!(ExitRecord::verify_at(&forged, now), Err(RecordError::WrongSigner));
    }

    #[test]
    fn rejects_record_stored_under_another_key() {
        let key = Keypair::generate_ed25519();
        let now = 1_000_000;
        let mut signed = record_for(&key, now + 3600).sign(&key).unwrap();
        signed.key = exit_record_key(&PeerId::random());
        assert_eq!(ExitRecord::verify_at(&signed, now), Err(RecordError::WrongKey));
    }

    #[test]
    fn rejects_tampered_payload() {
        let key = Keypair::generate_ed25519();
        let now = 1_000_000;
        let mut signed = record_for(&key, now + 3600).sign(&key).unwrap();
        let last = signed.value.len() - 40;
        signed.value[last] ^= 0x01;
        assert!(ExitRecord::verify_at(&signed, now).is_err());
    }

    #[test]
    fn rejects_expired_and_far_future_records() {
        let key = Keypair::generate_ed25519();
        let now = 1_000_000;
        let expired = record_for(&key, now - 1).sign(&key).unwrap();
        assert_eq!(ExitRecord::verify_at(&expired, now), Err(RecordError::Expired));
        let future = record_for(&key, now + 24 * 3600).sign(&key).unwrap();
        assert_eq!(ExitRecord::verify_at(&future, now), Err(RecordError::TooFarInFuture));
    }
}
