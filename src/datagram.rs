//! The datagram path: IP packets as UDP datagrams, client ⇄ relay ⇄ exit, next to the
//! circuit's stream. See docs/DESIGN.md §3.4.
//!
//! A stream delivers everything, in order, so one lost packet holds back all that follow
//! it, and the TCP connections inside the tunnel retransmit on top of the stream's own
//! retransmission ("TCP over TCP"). Datagrams don't wait for each other: a lost one is
//! lost, and only the connection it belonged to retransmits it.
//!
//! - Client and exit send datagrams only to the relay, which is publicly reachable, so
//!   an exit behind NAT needs no hole punching: its own datagrams open the way back.
//! - Two layers of encryption. Per hop ([`Offer`]: a circuit ID and a key the relay
//!   hands each side over the encrypted libp2p stream), so the bytes before and after
//!   the relay differ and the relay only forwards what the hop key authenticates.
//!   End to end ([`E2eSender`], [`E2eReceiver`]), with keys the exit sends the client
//!   inside the circuit's Noise handshake, so the relay can't read or alter packets.
//!   Both layers reject replays.
//! - The end-to-end keys move forward every [`crate::circuit::REKEY_EVERY`] packets,
//!   and old keys are forgotten, as on the stream.
//!
//! On the wire: `[circuit id: 8][counter: 8][hop ciphertext + tag]`, where the hop
//! plaintext is `[e2e counter: 8][e2e ciphertext + tag]` and the end-to-end plaintext a
//! padded packet ([`crate::framing::pad`]).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::circuit::REKEY_EVERY;
use crate::ratelimit::TokenBucket;

/// The UDP port nodes use for datagrams unless told otherwise. Relays must be reachable
/// on it; clients and exits only send from it.
pub const DEFAULT_PORT: u16 = 4002;
/// After this long without a valid datagram from the other end, packets go over the
/// stream again. An idle client sends a keepalive at least every ~16 s, which the exit
/// answers, so a working path never goes this quiet.
pub const STALE_AFTER: Duration = Duration::from_secs(20);
/// Bytes added to a padded packet: the hop header, two counters and two tags.
pub const OVERHEAD: usize = HOP_HEADER + TAG + E2E_HEADER + TAG;

const HOP_HEADER: usize = 16;
const E2E_HEADER: usize = 8;
const TAG: usize = 16;
const MAX_DATAGRAM: usize = 2048;
/// Datagrams queued for one endpoint before new ones are dropped.
const ENDPOINT_QUEUE: usize = 512;
/// Counters this far behind the newest are still accepted (reordering), once each.
const REPLAY_WINDOW: u64 = 1024;
/// How far ahead of the receiver's key epoch an authenticated packet may be. An honest
/// sender moves one epoch per [`REKEY_EVERY`] packets; this tolerates losing whole epochs.
const MAX_EPOCH_SKIP: u64 = 4;
/// While the path isn't confirmed: probe this often for the first [`FAST_PROBING`],
/// then every [`SLOW_PROBE`].
const FAST_PROBE: Duration = Duration::from_millis(500);
const FAST_PROBING: Duration = Duration::from_secs(10);
const SLOW_PROBE: Duration = Duration::from_secs(5);

// Nonce prefixes: each key is used in one direction only, but distinct prefixes keep
// the layers apart even so.
const TO_RELAY: u32 = 1;
const FROM_RELAY: u32 = 2;
const END_TO_END: u32 = 3;

/// What the relay tells one side of a circuit, over the circuit's stream.
#[derive(Clone, Serialize, Deserialize)]
pub struct Offer {
    /// The relay's UDP port; the IP is the one the libp2p connection uses.
    pub port: u16,
    /// Identifies this hop in every datagram. Random, and different on each hop.
    pub circuit: u64,
    pub key: [u8; 32],
}

impl Offer {
    fn random(port: u16) -> Self {
        Self {
            port,
            circuit: rand::random(),
            key: rand::random(),
        }
    }
}

impl Drop for Offer {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

fn nonce(prefix: u32, counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix.to_be_bytes());
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce.into()
}

/// `header || ciphertext || tag`, with the header authenticated as associated data.
fn seal(cipher: &ChaCha20Poly1305, prefix: u32, header: &[u8], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + plaintext.len() + TAG);
    out.extend_from_slice(header);
    out.extend_from_slice(plaintext);
    let (aad, body) = out.split_at_mut(header.len());
    let tag = cipher
        .encrypt_in_place_detached(&nonce(prefix, counter), aad, body)
        .expect("plaintext within ChaCha20-Poly1305 limits");
    out.extend_from_slice(&tag);
    out
}

/// The plaintext of `body || tag`, authenticated together with `header`.
fn open(cipher: &ChaCha20Poly1305, prefix: u32, header: &[u8], counter: u64, sealed: &[u8]) -> Option<Vec<u8>> {
    let split = sealed.len().checked_sub(TAG)?;
    let (body, tag) = sealed.split_at(split);
    let mut plaintext = body.to_vec();
    cipher
        .decrypt_in_place_detached(&nonce(prefix, counter), header, &mut plaintext, Tag::from_slice(tag))
        .ok()?;
    Some(plaintext)
}

fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?))
}

/// One hop's key: seals `[circuit][counter]` headers and checks them.
struct HopCipher {
    circuit: u64,
    cipher: ChaCha20Poly1305,
}

impl HopCipher {
    fn new(offer: &Offer) -> Self {
        Self {
            circuit: offer.circuit,
            cipher: ChaCha20Poly1305::new(&offer.key.into()),
        }
    }

    fn seal(&self, prefix: u32, counter: u64, payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; HOP_HEADER];
        header[..8].copy_from_slice(&self.circuit.to_be_bytes());
        header[8..].copy_from_slice(&counter.to_be_bytes());
        seal(&self.cipher, prefix, &header, counter, payload)
    }

    fn open(&self, prefix: u32, datagram: &[u8]) -> Option<(u64, Vec<u8>)> {
        let header = datagram.get(..HOP_HEADER)?;
        if read_u64(header)? != self.circuit {
            return None;
        }
        let counter = read_u64(&header[8..])?;
        Some((counter, open(&self.cipher, prefix, header, counter, &datagram[HOP_HEADER..])?))
    }
}

/// Accepts each counter at most once, and only within [`REPLAY_WINDOW`] of the newest.
#[derive(Default)]
struct ReplayWindow {
    newest: u64,
    /// Bit `i` is set if `newest - i` was seen.
    seen: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl ReplayWindow {
    /// Counters start at 1, so 0 is never valid.
    fn fresh(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if counter > self.newest {
            return true;
        }
        let age = self.newest - counter;
        age < REPLAY_WINDOW && self.seen[(age / 64) as usize] & (1 << (age % 64)) == 0
    }

    /// Records `counter`, which [`Self::fresh`] accepted and which authenticated.
    fn mark(&mut self, counter: u64) {
        if counter > self.newest {
            let shift = counter - self.newest;
            self.shift(shift);
            self.newest = counter;
        }
        let age = self.newest - counter;
        self.seen[(age / 64) as usize] |= 1 << (age % 64);
    }

    fn shift(&mut self, by: u64) {
        if by >= REPLAY_WINDOW {
            self.seen = Default::default();
            return;
        }
        let (words, bits) = ((by / 64) as usize, by % 64);
        let n = self.seen.len();
        for i in (0..n).rev() {
            let from = i.checked_sub(words);
            let high = from.map_or(0, |f| self.seen[f]);
            let carry = match from.and_then(|f| f.checked_sub(1)) {
                Some(f) if bits > 0 => self.seen[f] >> (64 - bits),
                _ => 0,
            };
            self.seen[i] = if bits == 0 { high } else { (high << bits) | carry };
        }
    }
}

/// Keys for the end-to-end layer, one per direction. The exit picks them and sends
/// them in its handshake message, which Noise encrypts with keys from both sides'
/// ephemeral keys (so they're forward secret like the stream's).
pub struct E2eSecrets {
    pub client_to_exit: Zeroizing<[u8; 32]>,
    pub exit_to_client: Zeroizing<[u8; 32]>,
}

impl E2eSecrets {
    pub fn random() -> Self {
        Self {
            client_to_exit: Zeroizing::new(rand::random()),
            exit_to_client: Zeroizing::new(rand::random()),
        }
    }
}

fn derive(key: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Blake2s256::new();
    hash.update(key);
    hash.update(label);
    Zeroizing::new(hash.finalize().into())
}

/// A key that moves forward one epoch at a time; earlier keys can't be recomputed.
#[derive(Clone)]
struct Ratchet {
    epoch: u64,
    key: Zeroizing<[u8; 32]>,
}

impl Ratchet {
    fn advance(&mut self) {
        self.key = derive(&self.key, b"dvpn ratchet");
        self.epoch += 1;
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&(*self.key).into())
    }
}

fn epoch_of(counter: u64) -> u64 {
    counter / REKEY_EVERY
}

pub struct E2eSender {
    ratchet: Ratchet,
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl E2eSender {
    pub fn new(key: &[u8; 32]) -> Self {
        let ratchet = Ratchet {
            epoch: 0,
            key: Zeroizing::new(*key),
        };
        Self {
            cipher: ratchet.cipher(),
            ratchet,
            counter: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.counter += 1;
        if epoch_of(self.counter) > self.ratchet.epoch {
            while epoch_of(self.counter) > self.ratchet.epoch {
                self.ratchet.advance();
            }
            self.cipher = self.ratchet.cipher();
        }
        seal(&self.cipher, END_TO_END, &self.counter.to_be_bytes(), self.counter, plaintext)
    }
}

pub struct E2eReceiver {
    current: Ratchet,
    cipher: ChaCha20Poly1305,
    /// The previous epoch's key, for packets reordered across a key change.
    previous: Option<(u64, ChaCha20Poly1305)>,
    window: ReplayWindow,
}

impl E2eReceiver {
    pub fn new(key: &[u8; 32]) -> Self {
        let current = Ratchet {
            epoch: 0,
            key: Zeroizing::new(*key),
        };
        Self {
            cipher: current.cipher(),
            current,
            previous: None,
            window: ReplayWindow::default(),
        }
    }

    pub fn open(&mut self, sealed: &[u8]) -> Option<Vec<u8>> {
        let header = sealed.get(..E2E_HEADER)?;
        let counter = read_u64(header)?;
        if !self.window.fresh(counter) {
            return None;
        }
        let epoch = epoch_of(counter);
        let body = &sealed[E2E_HEADER..];
        let plaintext = if epoch == self.current.epoch {
            open(&self.cipher, END_TO_END, header, counter, body)?
        } else if epoch < self.current.epoch {
            let (previous, cipher) = self.previous.as_ref()?;
            if *previous != epoch {
                return None;
            }
            open(cipher, END_TO_END, header, counter, body)?
        } else if epoch - self.current.epoch <= MAX_EPOCH_SKIP {
            // Try the later key; keep it only if the packet is genuine.
            let mut later = self.current.clone();
            let mut last = None;
            while later.epoch < epoch {
                last = Some((later.epoch, later.cipher()));
                later.advance();
            }
            let cipher = later.cipher();
            let plaintext = open(&cipher, END_TO_END, header, counter, body)?;
            self.previous = last.filter(|(e, _)| *e + 1 == epoch);
            self.current = later;
            self.cipher = cipher;
            plaintext
        } else {
            return None;
        };
        self.window.mark(counter);
        Some(plaintext)
    }
}

enum Route {
    Endpoint(mpsc::Sender<Vec<u8>>),
    Relay(Arc<RelayCircuit>, usize),
}

type Routes = Arc<Mutex<HashMap<u64, Route>>>;

/// A node's UDP socket, shared by the circuits it relays and the ones it ends.
pub struct Socket {
    udp: Arc<UdpSocket>,
    routes: Routes,
    port: u16,
    receiver: JoinHandle<()>,
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.receiver.abort();
    }
}

impl Socket {
    /// Binds UDP `port` on all IPv4 addresses, or any free port if that one is taken
    /// (or `port` is 0). Must be called inside a Tokio runtime.
    pub fn bind(port: u16) -> io::Result<Arc<Self>> {
        let std_socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
            .or_else(|_| std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))?;
        std_socket.set_nonblocking(true)?;
        let udp = Arc::new(UdpSocket::from_std(std_socket)?);
        let port = udp.local_addr()?.port();
        let routes: Routes = Arc::default();
        let receiver = tokio::spawn(receive(udp.clone(), routes.clone()));
        Ok(Arc::new(Self {
            udp,
            routes,
            port,
            receiver,
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Relays one circuit: returns the offers for its two sides (client, exit); the
    /// circuit is forwarded while the returned guard lives.
    pub fn relay(self: &Arc<Self>, rate_mbps: u64) -> Option<(RelayGuard, Offer, Offer)> {
        let (a, b) = (Offer::random(self.port), Offer::random(self.port));
        if a.circuit == b.circuit {
            return None;
        }
        let circuit = Arc::new(RelayCircuit {
            hops: [RelayHop::new(&a, rate_mbps), RelayHop::new(&b, rate_mbps)],
        });
        let mut routes = self.routes.lock().expect("routes lock");
        if routes.contains_key(&a.circuit) || routes.contains_key(&b.circuit) {
            return None;
        }
        routes.insert(a.circuit, Route::Relay(circuit.clone(), 0));
        routes.insert(b.circuit, Route::Relay(circuit, 1));
        let guard = RelayGuard {
            routes: self.routes.clone(),
            ids: [a.circuit, b.circuit],
        };
        Some((guard, a, b))
    }

    /// Ends a circuit at this node: datagrams for `offer`'s hop, through `relay`.
    pub fn endpoint(self: &Arc<Self>, offer: &Offer, relay: Ipv4Addr) -> Option<(EndpointTx, EndpointRx)> {
        let (tx, rx) = mpsc::channel(ENDPOINT_QUEUE);
        {
            let mut routes = self.routes.lock().expect("routes lock");
            if routes.contains_key(&offer.circuit) {
                return None;
            }
            routes.insert(offer.circuit, Route::Endpoint(tx));
        }
        let hop = Arc::new(HopCipher::new(offer));
        let sender = EndpointTx {
            udp: self.udp.clone(),
            relay: SocketAddr::V4(SocketAddrV4::new(relay, offer.port)),
            hop: hop.clone(),
            counter: AtomicU64::new(0),
        };
        let receiver = EndpointRx {
            rx,
            hop,
            window: ReplayWindow::default(),
            routes: self.routes.clone(),
            circuit: offer.circuit,
        };
        Some((sender, receiver))
    }
}

/// Reads datagrams and hands each to its circuit: forwarded at once if relayed, queued
/// if it ends here. Unknown circuits and malformed datagrams cost a map lookup.
async fn receive(udp: Arc<UdpSocket>, routes: Routes) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, from) = match udp.recv_from(&mut buf).await {
            Ok(received) => received,
            // E.g. ICMP port unreachable for an earlier send; keep going.
            Err(_) => continue,
        };
        let datagram = &buf[..n];
        let Some(circuit) = read_u64(datagram) else { continue };
        let route = match routes.lock().expect("routes lock").get(&circuit) {
            Some(Route::Endpoint(tx)) => Err(tx.clone()),
            Some(Route::Relay(circuit, side)) => Ok((circuit.clone(), *side)),
            None => continue,
        };
        match route {
            Ok((circuit, side)) => circuit.forward(side, datagram, from, &udp),
            // A full queue means the reader is behind; drop like a router would.
            Err(tx) => {
                let _ = tx.try_send(datagram.to_vec());
            }
        }
    }
}

struct RelayHop {
    cipher: HopCipher,
    /// Where this side sends from, learned from its newest authenticated datagram.
    peer: Mutex<Option<SocketAddr>>,
    window: Mutex<ReplayWindow>,
    counter: AtomicU64,
    /// Limits what is forwarded *to* this side.
    bucket: Mutex<TokenBucket>,
}

impl RelayHop {
    fn new(offer: &Offer, rate_mbps: u64) -> Self {
        Self {
            cipher: HopCipher::new(offer),
            peer: Mutex::new(None),
            window: Mutex::new(ReplayWindow::default()),
            counter: AtomicU64::new(0),
            bucket: Mutex::new(TokenBucket::from_mbps(rate_mbps)),
        }
    }
}

struct RelayCircuit {
    hops: [RelayHop; 2],
}

impl RelayCircuit {
    fn forward(&self, side: usize, datagram: &[u8], from: SocketAddr, udp: &UdpSocket) {
        let (src, dst) = (&self.hops[side], &self.hops[1 - side]);
        let Some((counter, payload)) = src.cipher.open(TO_RELAY, datagram) else {
            return;
        };
        {
            let mut window = src.window.lock().expect("window lock");
            if !window.fresh(counter) {
                return;
            }
            let newest = counter > window.newest;
            window.mark(counter);
            // Only the newest datagram moves the address (a NAT may rebind), so a
            // replayed old one from elsewhere can't redirect the circuit.
            if newest {
                *src.peer.lock().expect("peer lock") = Some(from);
            }
        }
        let Some(to) = *dst.peer.lock().expect("peer lock") else {
            return; // The other side hasn't sent anything yet.
        };
        if !dst.bucket.lock().expect("bucket lock").try_take(payload.len()) {
            return;
        }
        let counter = dst.counter.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = udp.try_send_to(&dst.cipher.seal(FROM_RELAY, counter, &payload), to);
    }
}

/// Stops relaying a circuit when dropped.
pub struct RelayGuard {
    routes: Routes,
    ids: [u64; 2],
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        let mut routes = self.routes.lock().expect("routes lock");
        for id in self.ids {
            routes.remove(&id);
        }
    }
}

/// Sends an endpoint's datagrams to the relay.
pub struct EndpointTx {
    udp: Arc<UdpSocket>,
    relay: SocketAddr,
    hop: Arc<HopCipher>,
    counter: AtomicU64,
}

impl EndpointTx {
    pub async fn send(&self, e2e: &[u8]) -> io::Result<()> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        self.udp.send_to(&self.hop.seal(TO_RELAY, counter, e2e), self.relay).await.map(drop)
    }
}

/// An endpoint's incoming datagrams, with the hop layer removed. Unregisters the
/// circuit when dropped.
pub struct EndpointRx {
    rx: mpsc::Receiver<Vec<u8>>,
    hop: Arc<HopCipher>,
    window: ReplayWindow,
    routes: Routes,
    circuit: u64,
}

impl EndpointRx {
    /// The next authenticated hop payload (an end-to-end datagram); `None` once the
    /// socket is gone.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            let datagram = self.rx.recv().await?;
            let Some((counter, payload)) = self.hop.open(FROM_RELAY, &datagram) else {
                continue;
            };
            if self.window.fresh(counter) {
                self.window.mark(counter);
                return Some(payload);
            }
        }
    }
}

impl Drop for EndpointRx {
    fn drop(&mut self) {
        self.routes.lock().expect("routes lock").remove(&self.circuit);
    }
}

/// When a valid datagram last arrived from the other end, shared by a tunnel's halves.
#[derive(Clone, Default)]
pub struct Liveness(Arc<Mutex<Option<Instant>>>);

impl Liveness {
    pub fn heard(&self) {
        *self.0.lock().expect("liveness lock") = Some(Instant::now());
    }

    /// Datagrams reach us, so ours (very likely) reach the other end too.
    pub fn alive(&self) -> bool {
        self.0.lock().expect("liveness lock").is_some_and(|at| at.elapsed() < STALE_AFTER)
    }

    /// Nothing arrived for `long`.
    pub fn quiet_for(&self, long: Duration) -> bool {
        self.0.lock().expect("liveness lock").is_none_or(|at| at.elapsed() >= long)
    }
}

/// Sends `probe` (an empty, padded packet: a keepalive the other end answers) until
/// datagrams arrive, then again whenever they stop. Runs until aborted.
pub async fn probe<F, Fut>(liveness: Liveness, mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    let started = Instant::now();
    let mut confirmed = false;
    loop {
        if liveness.alive() {
            if !confirmed {
                debug!("datagram path confirmed");
                confirmed = true;
            }
        } else {
            if confirmed {
                info!("datagrams stopped arriving; using the stream until they're back");
                confirmed = false;
            }
            let _ = probe().await;
        }
        let pause = if started.elapsed() < FAST_PROBING { FAST_PROBE } else { SLOW_PROBE };
        tokio::time::sleep(pause).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (E2eSender, E2eReceiver) {
        let key = [7u8; 32];
        (E2eSender::new(&key), E2eReceiver::new(&key))
    }

    #[test]
    fn end_to_end_round_trips_and_rejects_tampering_and_replays() {
        let (mut tx, mut rx) = pair();
        let sealed = tx.seal(b"hello");
        assert!(!sealed.windows(5).any(|w| w == b"hello"), "encrypted");
        let mut tampered = sealed.clone();
        tampered[10] ^= 1;
        assert_eq!(rx.open(&tampered), None);
        assert_eq!(rx.open(&sealed).as_deref(), Some(&b"hello"[..]));
        assert_eq!(rx.open(&sealed), None, "replayed");
        assert_eq!(E2eReceiver::new(&[8; 32]).open(&tx.seal(b"x")), None, "wrong key");
    }

    #[test]
    fn reordered_packets_are_accepted_once_within_the_window() {
        let (mut tx, mut rx) = pair();
        let packets: Vec<_> = (0..2000).map(|i| tx.seal(&u32::to_be_bytes(i))).collect();
        assert!(rx.open(&packets[1500]).is_some());
        assert!(rx.open(&packets[1000]).is_some(), "late, but within the window");
        assert!(rx.open(&packets[1000]).is_none(), "only once");
        assert!(rx.open(&packets[100]).is_none(), "too old");
        assert!(rx.open(&packets[1999]).is_some());
        assert!(rx.open(&packets[1501]).is_some());
    }

    #[test]
    fn keys_move_forward_and_tolerate_reordering_across_a_change() {
        let (mut tx, mut rx) = pair();
        let packets: Vec<_> = (0..REKEY_EVERY + 10).map(|_| tx.seal(b"p")).collect();
        let boundary = (REKEY_EVERY - 1) as usize; // The first packet of epoch 1.
        assert!(rx.open(&packets[boundary + 3]).is_some(), "the new key is derived");
        assert!(rx.open(&packets[boundary - 2]).is_some(), "a straggler from the old epoch");
        assert_eq!(rx.current.epoch, 1);
        // Many epochs later (lost packets), the receiver catches up, but not unboundedly.
        let mut far = E2eSender::new(&[7; 32]);
        far.counter = REKEY_EVERY * 3;
        assert!(E2eReceiver::new(&[7; 32]).open(&far.seal(b"later")).is_some());
        let mut too_far = E2eSender::new(&[7; 32]);
        too_far.counter = REKEY_EVERY * (MAX_EPOCH_SKIP + 2);
        assert!(E2eReceiver::new(&[7; 32]).open(&too_far.seal(b"x")).is_none());
    }

    #[test]
    fn replay_window_shifts_correctly() {
        let mut w = ReplayWindow::default();
        for n in [1, 2, 3, 70, 65, 200, 130] {
            assert!(w.fresh(n), "{n}");
            w.mark(n);
            assert!(!w.fresh(n), "{n} twice");
        }
        for n in [4, 64, 66, 129, 199] {
            assert!(w.fresh(n), "{n} not seen yet");
        }
        w.mark(5000);
        assert!(!w.fresh(200), "fell out of the window");
        assert!(w.fresh(4000));
        assert!(!w.fresh(0));
    }

    #[test]
    fn hop_layer_is_bound_to_its_circuit_and_key() {
        let offer = Offer::random(4002);
        let hop = HopCipher::new(&offer);
        let datagram = hop.seal(TO_RELAY, 1, b"payload");
        assert_eq!(hop.open(TO_RELAY, &datagram), Some((1, b"payload".to_vec())));
        assert_eq!(hop.open(FROM_RELAY, &datagram), None, "the other direction");
        let mut moved = datagram.clone();
        moved[..8].copy_from_slice(&(offer.circuit ^ 1).to_be_bytes());
        assert_eq!(hop.open(TO_RELAY, &moved), None, "another circuit's ID");
        assert_eq!(HopCipher::new(&Offer::random(4002)).open(TO_RELAY, &datagram), None);
    }

    async fn recv(rx: &mut EndpointRx) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn a_relay_forwards_between_two_endpoints_and_re_encrypts() {
        let relay = Socket::bind(0).unwrap();
        let (client_node, exit_node) = (Socket::bind(0).unwrap(), Socket::bind(0).unwrap());
        let (_guard, a, b) = relay.relay(0).unwrap();
        let (client_tx, mut client_rx) = client_node.endpoint(&a, Ipv4Addr::LOCALHOST).unwrap();
        let (exit_tx, mut exit_rx) = exit_node.endpoint(&b, Ipv4Addr::LOCALHOST).unwrap();

        // Until the exit has sent something, the relay doesn't know where it is.
        exit_tx.send(b"exit here").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client_tx.send(b"to the exit").await.unwrap();
        assert_eq!(recv(&mut exit_rx).await, b"to the exit");
        exit_tx.send(b"to the client").await.unwrap();
        assert_eq!(recv(&mut client_rx).await, b"to the client");

        // The bytes on each hop differ: the client's hop key can't open the exit's hop.
        assert_ne!(a.key, b.key);
        assert_ne!(a.circuit, b.circuit);
    }

    #[tokio::test]
    async fn a_relay_drops_what_its_hop_key_doesnt_authenticate() {
        let relay = Socket::bind(0).unwrap();
        let node = Socket::bind(0).unwrap();
        let (_guard, a, b) = relay.relay(0).unwrap();
        let (exit_tx, mut exit_rx) = node.endpoint(&b, Ipv4Addr::LOCALHOST).unwrap();
        exit_tx.send(b"hi").await.unwrap();
        // Right circuit ID, wrong key.
        let forged = Offer { key: [1; 32], ..a.clone() };
        let attacker = Socket::bind(0).unwrap();
        let (forger, _rx) = attacker.endpoint(&forged, Ipv4Addr::LOCALHOST).unwrap();
        forger.send(b"forged").await.unwrap();
        let got = tokio::time::timeout(Duration::from_millis(300), exit_rx.recv()).await;
        assert!(got.is_err(), "nothing forwarded");
    }
}
