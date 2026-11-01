//! Circuits: client → entry relay (splice) → exit, with an end-to-end Noise_NK session.
//!
//! - `/dvpn/splice/1`: the client asks a relay to connect it to an exit. The relay then
//!   pipes bytes both ways without being able to read them.
//! - `/dvpn/exit/1`: the Noise_NK handshake and encrypted, padded IP packets. The client
//!   has no static key, so the exit cannot identify or link clients. An empty packet is
//!   a keepalive: padded and encrypted, it looks like any small packet to a relay.
//!
//! See docs/DESIGN.md §3.4.

use std::any::Any;
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::io::{ReadHalf, WriteHalf};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tracing::debug;
use zeroize::Zeroizing;

use crate::addrs;
use crate::framing::{MAX_FRAME, MAX_PADDED_PACKET, pad, read_frame, unpad, write_frame};
use crate::identity::NOISE_PARAMS;
use crate::node::NodeHandle;
use crate::ratelimit::TokenBucket;
use crate::records::MAX_RECORD_ADDRS;

pub const SPLICE_PROTOCOL: StreamProtocol = StreamProtocol::new("/dvpn/splice/1");
pub const EXIT_PROTOCOL: StreamProtocol = StreamProtocol::new("/dvpn/exit/1");

/// Largest IP packet carried through a circuit.
pub const MTU: u16 = 1400;
const _: () = assert!(MTU as usize <= MAX_PADDED_PACKET);

const PROLOGUE: &[u8] = b"dvpn-circuit-v1";
const PROTOCOL_VERSION: u8 = 1;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const EXIT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SPLICES: usize = 64;

/// The client sends a keepalive after this long without sending or receiving anything;
/// the exit answers each one.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// The client gives up on a circuit after hearing nothing from the exit for this long.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// The exit drops a session after hearing nothing from the client for this long.
pub const EXIT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const SPLICE_OK: u8 = 0;
const SPLICE_EXIT_UNREACHABLE: u8 = 1;
const SPLICE_REFUSED: u8 = 2;

/// Exit virtual addresses: 10.77.0.2 – 10.77.255.254 (10.77.0.1 is the exit itself).
const POOL_FIRST: u32 = u32::from_be_bytes([10, 77, 0, 2]);
const POOL_LAST: u32 = u32::from_be_bytes([10, 77, 255, 254]);

#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("relay refused the splice request (not a relay, or busy)")]
    RelayRefused,
    #[error("could not connect to the relay: {0}")]
    RelayUnreachable(String),
    #[error("relay could not reach the exit (not an exit, offline, or busy)")]
    ExitUnreachable,
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("timed out")]
    Timeout,
    #[error("message failed authentication; tunnel closed")]
    Integrity,
    #[error("packet larger than MTU {MTU}")]
    PacketTooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<snow::Error> for CircuitError {
    fn from(e: snow::Error) -> Self {
        Self::Handshake(e.to_string())
    }
}

#[derive(Serialize, Deserialize)]
struct SpliceRequest {
    exit: Vec<u8>,
    addrs: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct ClientHello {
    version: u8,
}

#[derive(Serialize, Deserialize)]
struct ExitHello {
    assigned_ip: [u8; 4],
    mtu: u16,
}

type BoxStream = Box<dyn AsyncReadWrite>;
trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Resources (IP lease, session slot) that must live as long as either tunnel half.
type Guard = Arc<dyn Any + Send + Sync>;

/// An established, encrypted tunnel carrying IP packets.
pub struct Tunnel {
    /// The client's virtual address inside the exit's network.
    pub assigned_ip: Ipv4Addr,
    pub mtu: u16,
    pub tx: TunnelSender,
    pub rx: TunnelReceiver,
}

pub struct TunnelSender {
    writer: WriteHalf<BoxStream>,
    noise: Arc<Mutex<snow::TransportState>>,
    _guard: Option<Guard>,
}

pub struct TunnelReceiver {
    reader: ReadHalf<BoxStream>,
    noise: Arc<Mutex<snow::TransportState>>,
    _guard: Option<Guard>,
}

impl TunnelSender {
    pub async fn send(&mut self, packet: &[u8]) -> Result<(), CircuitError> {
        if packet.len() > MTU as usize {
            return Err(CircuitError::PacketTooLarge);
        }
        let plaintext = pad(packet).ok_or(CircuitError::PacketTooLarge)?;
        let mut frame = vec![0u8; plaintext.len() + 16];
        let n = self.noise.lock().expect("noise lock").write_message(&plaintext, &mut frame)?;
        write_frame(&mut self.writer, &frame[..n]).await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), CircuitError> {
        self.writer.close().await?;
        Ok(())
    }
}

impl TunnelReceiver {
    /// The next packet; `Ok(None)` when the peer closed the tunnel cleanly.
    /// Any frame that fails authentication ends the tunnel with [`CircuitError::Integrity`].
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, CircuitError> {
        let Some(frame) = read_frame(&mut self.reader).await? else {
            return Ok(None);
        };
        let mut plaintext = vec![0u8; frame.len()];
        let n = self
            .noise
            .lock()
            .expect("noise lock")
            .read_message(&frame, &mut plaintext)
            .map_err(|_| CircuitError::Integrity)?;
        let packet = unpad(&plaintext[..n]).ok_or(CircuitError::Integrity)?;
        Ok(Some(packet.to_vec()))
    }
}

fn into_tunnel(stream: BoxStream, noise: snow::TransportState, hello: ExitHello, guard: Option<Guard>) -> Tunnel {
    let (reader, writer) = stream.split();
    let noise = Arc::new(Mutex::new(noise));
    Tunnel {
        assigned_ip: Ipv4Addr::from(hello.assigned_ip),
        mtu: hello.mtu,
        tx: TunnelSender {
            writer,
            noise: noise.clone(),
            _guard: guard.clone(),
        },
        rx: TunnelReceiver {
            reader,
            noise,
            _guard: guard,
        },
    }
}

async fn read_handshake_frame(stream: &mut BoxStream) -> Result<Vec<u8>, CircuitError> {
    read_frame(stream)
        .await?
        .ok_or_else(|| CircuitError::Handshake("stream closed during handshake".into()))
}

/// Client side of Noise_NK: authenticates the exit by its static key; sends no identity.
pub async fn client_handshake<S>(stream: S, exit_static: &[u8; 32]) -> Result<Tunnel, CircuitError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let mut noise = snow::Builder::new(NOISE_PARAMS.parse()?)
        .remote_public_key(exit_static)?
        .prologue(PROLOGUE)?
        .build_initiator()?;
    let mut buf = vec![0u8; MAX_FRAME];

    let hello = postcard::to_stdvec(&ClientHello { version: PROTOCOL_VERSION }).expect("serializable");
    let n = noise.write_message(&hello, &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    let reply = read_handshake_frame(&mut stream).await?;
    let n = noise.read_message(&reply, &mut buf)?;
    let hello: ExitHello =
        postcard::from_bytes(&buf[..n]).map_err(|_| CircuitError::Handshake("malformed exit hello".into()))?;
    if hello.mtu == 0 || hello.mtu > MTU {
        return Err(CircuitError::Handshake("exit offered an invalid MTU".into()));
    }
    Ok(into_tunnel(stream, noise.into_transport_mode()?, hello, None))
}

/// Exit side of Noise_NK. `guard` is kept alive for as long as the tunnel exists.
pub async fn exit_handshake<S>(
    stream: S,
    static_private: &[u8],
    assigned_ip: Ipv4Addr,
    guard: Option<Guard>,
) -> Result<Tunnel, CircuitError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let mut noise = snow::Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(static_private)?
        .prologue(PROLOGUE)?
        .build_responder()?;
    let mut buf = vec![0u8; MAX_FRAME];

    let first = read_handshake_frame(&mut stream).await?;
    let n = noise.read_message(&first, &mut buf)?;
    let hello: ClientHello =
        postcard::from_bytes(&buf[..n]).map_err(|_| CircuitError::Handshake("malformed client hello".into()))?;
    if hello.version != PROTOCOL_VERSION {
        return Err(CircuitError::Handshake(format!("unsupported version {}", hello.version)));
    }

    let hello = ExitHello {
        assigned_ip: assigned_ip.octets(),
        mtu: MTU,
    };
    let payload = postcard::to_stdvec(&hello).expect("serializable");
    let n = noise.write_message(&payload, &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    Ok(into_tunnel(stream, noise.into_transport_mode()?, hello, guard))
}

/// Client: asks `relay` to splice to `exit`, then runs the Noise_NK handshake through it.
pub async fn open_via_relay(
    handle: &NodeHandle,
    relay: PeerId,
    exit: PeerId,
    exit_addrs: &[Multiaddr],
    exit_static: &[u8; 32],
) -> Result<Tunnel, CircuitError> {
    let mut stream = handle
        .control()
        .open_stream(relay, SPLICE_PROTOCOL)
        .await
        .map_err(|e| match e {
            libp2p_stream::OpenStreamError::UnsupportedProtocol(_) => CircuitError::RelayRefused,
            other => CircuitError::RelayUnreachable(addrs::redact(&other.to_string())),
        })?;

    let request = SpliceRequest {
        exit: exit.to_bytes(),
        addrs: exit_addrs.iter().take(MAX_RECORD_ADDRS).map(|a| a.to_vec()).collect(),
    };
    write_frame(&mut stream, &postcard::to_stdvec(&request).expect("serializable")).await?;

    let status = timeout(EXIT_CONNECT_TIMEOUT + HANDSHAKE_TIMEOUT, read_frame(&mut stream))
        .await
        .map_err(|_| CircuitError::Timeout)??;
    match status.as_deref() {
        Some([SPLICE_OK]) => {}
        Some([SPLICE_EXIT_UNREACHABLE]) => return Err(CircuitError::ExitUnreachable),
        _ => return Err(CircuitError::RelayRefused),
    }

    timeout(HANDSHAKE_TIMEOUT, client_handshake(stream, exit_static))
        .await
        .map_err(|_| CircuitError::Timeout)?
}

/// Relay: accepts splice requests and pipes them to the requested exit.
pub(crate) async fn serve_splices(
    handle: NodeHandle,
    mut incoming: libp2p_stream::IncomingStreams,
    rate_mbps: u64,
    allow_private: bool,
) {
    let slots = Arc::new(Semaphore::new(MAX_SPLICES));
    while let Some((from, stream)) = incoming.next().await {
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!("splice limit reached; dropping request");
            continue;
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = splice(&handle, from, stream, rate_mbps, allow_private).await {
                debug!("splice ended: {e:#}");
            }
        });
    }
}

async fn splice(
    handle: &NodeHandle,
    from: PeerId,
    mut client: libp2p::Stream,
    rate_mbps: u64,
    allow_private: bool,
) -> anyhow::Result<()> {
    let request = timeout(HANDSHAKE_TIMEOUT, read_frame(&mut client))
        .await??
        .ok_or_else(|| anyhow::anyhow!("closed before request"))?;
    let request: SpliceRequest = postcard::from_bytes(&request)?;
    let exit = PeerId::from_bytes(&request.exit)?;
    if exit == from || exit == handle.peer_id() {
        write_frame(&mut client, &[SPLICE_REFUSED]).await?;
        anyhow::bail!("refused splice to the requester or to ourselves");
    }
    let addrs = splice_addrs(request.addrs, allow_private);

    let connect = async {
        if !addrs.is_empty() {
            // Already-connected or failed dials are fine: open_stream retries via the DHT.
            let _ = handle.dial(exit, addrs, false).await;
        }
        handle.control().open_stream(exit, EXIT_PROTOCOL).await
    };
    let exit_stream = match timeout(EXIT_CONNECT_TIMEOUT, connect).await {
        Ok(Ok(stream)) => stream,
        _ => {
            write_frame(&mut client, &[SPLICE_EXIT_UNREACHABLE]).await?;
            anyhow::bail!("exit unreachable");
        }
    };
    write_frame(&mut client, &[SPLICE_OK]).await?;
    pipe(client, exit_stream, rate_mbps).await;
    Ok(())
}

/// The exit addresses from a splice request that this relay is willing to dial. The
/// request comes from an untrusted client, so loopback and LAN addresses are dropped
/// (unless the network is LAN-only).
fn splice_addrs(raw: Vec<Vec<u8>>, allow_private: bool) -> Vec<Multiaddr> {
    raw.into_iter()
        .take(MAX_RECORD_ADDRS)
        .filter_map(|a| Multiaddr::try_from(a).ok())
        .filter(|a| addrs::is_dialable_for_others(a, allow_private))
        .collect()
}

/// Copies bytes both ways (rate-limited) until either side closes, then closes both.
async fn pipe(a: libp2p::Stream, b: libp2p::Stream, rate_mbps: u64) {
    let (a_read, mut a_write) = a.split();
    let (b_read, mut b_write) = b.split();
    {
        let up = copy_limited(a_read, &mut b_write, rate_mbps);
        let down = copy_limited(b_read, &mut a_write, rate_mbps);
        futures::pin_mut!(up, down);
        let _ = futures::future::select(up, down).await;
    }
    let _ = a_write.close().await;
    let _ = b_write.close().await;
}

async fn copy_limited<R, W>(mut from: R, to: &mut W, rate_mbps: u64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bucket = TokenBucket::from_mbps(rate_mbps);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        bucket.take(n).await;
        to.write_all(&buf[..n]).await?;
        to.flush().await?;
    }
}

/// An incoming tunnel at an exit.
pub struct ExitSession {
    /// The peer the session arrived from: the client's entry relay, never the client.
    pub via_peer: PeerId,
    pub tunnel: Tunnel,
}

/// Exit: accepts tunnels, assigns virtual IPs and hands sessions to `sessions`.
pub(crate) async fn serve_exit(
    mut incoming: libp2p_stream::IncomingStreams,
    static_private: Zeroizing<Vec<u8>>,
    max_sessions: usize,
    pool: IpPool,
    sessions: mpsc::Sender<ExitSession>,
) {
    let slots = Arc::new(Semaphore::new(max_sessions));
    let per_relay = RelayQuota::new(per_relay_limit(max_sessions));
    let static_private = Arc::new(static_private);
    while let Some((via_peer, stream)) = incoming.next().await {
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!("exit session limit reached; dropping request");
            continue;
        };
        let Some(ticket) = per_relay.acquire(via_peer) else {
            debug!("too many sessions through one relay; dropping request");
            continue;
        };
        let Some(lease) = pool.lease() else {
            debug!("exit address pool exhausted; dropping request");
            continue;
        };
        let key = static_private.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let ip = lease.ip;
            let guard: Guard = Arc::new((lease, slot, ticket));
            match timeout(HANDSHAKE_TIMEOUT, exit_handshake(stream, &key, ip, Some(guard))).await {
                Ok(Ok(tunnel)) => {
                    let _ = sessions.send(ExitSession { via_peer, tunnel }).await;
                }
                Ok(Err(e)) => debug!("exit handshake failed: {e}"),
                Err(_) => debug!("exit handshake timed out"),
            }
        });
    }
}

/// Sessions allowed through one relay. Exits can't tell clients apart (that's the point),
/// but they can stop a single relay, and so a single client, from taking every slot.
fn per_relay_limit(max_sessions: usize) -> usize {
    (max_sessions / 4).max(2)
}

/// Counts sessions per relay; a [`RelayTicket`] gives its place back when dropped.
#[derive(Clone)]
struct RelayQuota {
    limit: usize,
    counts: Arc<Mutex<HashMap<PeerId, usize>>>,
}

struct RelayTicket {
    relay: PeerId,
    quota: RelayQuota,
}

impl RelayQuota {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            counts: Arc::default(),
        }
    }

    fn acquire(&self, relay: PeerId) -> Option<RelayTicket> {
        let mut counts = self.counts.lock().expect("quota lock");
        let count = counts.entry(relay).or_default();
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(RelayTicket {
            relay,
            quota: self.clone(),
        })
    }
}

impl Drop for RelayTicket {
    fn drop(&mut self) {
        let mut counts = self.quota.counts.lock().expect("quota lock");
        if let Some(count) = counts.get_mut(&self.relay) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.relay);
            }
        }
    }
}

/// Allocates unique virtual IPs; an address returns to the pool when its lease drops.
///
/// Every exit uses the same range, so a machine that is both a client and an exit could
/// be handed its own tunnel address by a remote exit and also lease it locally. Leases
/// start at a random point to make that rare, the client's own address can be
/// [reserved](Self::reserve), and the client checks [`Self::is_leased`] for the rest.
#[derive(Clone, Default)]
pub struct IpPool {
    state: Arc<Mutex<PoolState>>,
}

#[derive(Default)]
struct PoolState {
    used: BTreeSet<u32>,
    reserved: Option<u32>,
}

pub struct IpLease {
    pub ip: Ipv4Addr,
    pool: IpPool,
}

impl IpPool {
    pub fn lease(&self) -> Option<IpLease> {
        self.lease_from(rand::random_range(POOL_FIRST..=POOL_LAST))
    }

    /// The first free address at or after `start`, wrapping around.
    fn lease_from(&self, start: u32) -> Option<IpLease> {
        let mut state = self.state.lock().expect("pool lock");
        let free = (start..=POOL_LAST)
            .chain(POOL_FIRST..start)
            .find(|ip| !state.used.contains(ip) && state.reserved != Some(*ip))?;
        state.used.insert(free);
        Some(IpLease {
            ip: Ipv4Addr::from(free),
            pool: self.clone(),
        })
    }

    /// Keeps `ip` (this machine's own tunnel address) out of new leases.
    pub fn reserve(&self, ip: Option<Ipv4Addr>) {
        self.state.lock().expect("pool lock").reserved = ip.map(u32::from);
    }

    pub fn is_leased(&self, ip: Ipv4Addr) -> bool {
        self.state.lock().expect("pool lock").used.contains(&u32::from(ip))
    }
}

impl Drop for IpLease {
    fn drop(&mut self) {
        self.pool.state.lock().expect("pool lock").used.remove(&u32::from(self.ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_relay_cannot_take_every_exit_session() {
        assert_eq!(per_relay_limit(16), 4);
        assert_eq!(per_relay_limit(64), 16);
        assert_eq!(per_relay_limit(3), 2, "small exits still allow some sharing of a relay");

        let quota = RelayQuota::new(2);
        let (busy, other) = (PeerId::random(), PeerId::random());
        let first = quota.acquire(busy).unwrap();
        let _second = quota.acquire(busy).unwrap();
        assert!(quota.acquire(busy).is_none(), "third session through the same relay");
        assert!(quota.acquire(other).is_some(), "other relays are unaffected");
        drop(first);
        assert!(quota.acquire(busy).is_some(), "a closed session frees its place");
    }

    #[test]
    fn relays_ignore_internal_addresses_in_splice_requests() {
        let raw = |addrs: &[&str]| addrs.iter().map(|a| a.parse::<Multiaddr>().unwrap().to_vec()).collect::<Vec<_>>();
        let request = raw(&["/ip4/127.0.0.1/tcp/22", "/ip4/192.168.1.1/tcp/80", "/ip4/203.0.114.9/tcp/4001"]);
        let dialed = splice_addrs(request.clone(), false);
        assert_eq!(dialed, ["/ip4/203.0.114.9/tcp/4001".parse::<Multiaddr>().unwrap()]);
        assert_eq!(splice_addrs(request, true).len(), 3, "LAN-only networks keep private addresses");
        assert!(splice_addrs(vec![b"garbage".to_vec()], true).is_empty());
    }

    fn in_pool(ip: Ipv4Addr) -> bool {
        (POOL_FIRST..=POOL_LAST).contains(&u32::from(ip))
    }

    #[test]
    fn pool_hands_out_unique_addresses_and_releases_them() {
        let pool = IpPool::default();
        let leases: Vec<IpLease> = (0..100).map(|_| pool.lease().unwrap()).collect();
        let unique: BTreeSet<Ipv4Addr> = leases.iter().map(|l| l.ip).collect();
        assert_eq!(unique.len(), leases.len());
        assert!(unique.iter().all(|&ip| in_pool(ip)));

        let ip = leases[0].ip;
        assert!(pool.is_leased(ip));
        drop(leases);
        assert!(!pool.is_leased(ip));
    }

    #[test]
    fn pool_starts_at_random_addresses() {
        // Two independent exits must not both start at 10.77.0.2.
        let firsts: BTreeSet<Ipv4Addr> = (0..20).map(|_| IpPool::default().lease().unwrap().ip).collect();
        assert!(firsts.len() > 1, "every pool started at {firsts:?}");
    }

    #[test]
    fn pool_never_leases_the_reserved_address() {
        let pool = IpPool::default();
        let own = Ipv4Addr::new(10, 77, 3, 9);
        pool.reserve(Some(own));
        let next = pool.lease_from(u32::from(own)).unwrap();
        assert_eq!(next.ip, Ipv4Addr::new(10, 77, 3, 10), "reserved address was leased");
        // Scanning wraps around at the end of the range.
        let last = pool.lease_from(POOL_LAST).unwrap();
        assert_eq!(u32::from(last.ip), POOL_LAST);
        assert_eq!(u32::from(pool.lease_from(POOL_LAST).unwrap().ip), POOL_FIRST);
        pool.reserve(None);
        assert_eq!(pool.lease_from(u32::from(own)).unwrap().ip, own);
    }
}
