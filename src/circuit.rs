//! Circuits: client → entry relay (splice) → exit, with an end-to-end Noise_NK session.
//!
//! - `/dvpn/splice/2`: the client asks a relay to connect it to an exit. The relay then
//!   pipes bytes both ways without being able to read them, and offers both sides a
//!   [`datagram`](crate::datagram) path through it.
//! - `/dvpn/exit/2`: the relay's offer, then the Noise_NK handshake and encrypted,
//!   padded IP packets. The client has no static key, so the exit cannot identify or
//!   link clients. An empty packet is a keepalive: padded and encrypted, it looks like
//!   any small packet to a relay.
//!
//! Packets go over the stream until datagrams arrive from the other end, then as
//! datagrams for as long as they keep arriving. The stream stays open: it carries the
//! handshake, packets whenever datagrams don't get through, and the circuit's lifetime.
//!
//! See docs/DESIGN.md §3.4.

use std::any::Any;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
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
use crate::datagram::{self, E2eReceiver, E2eSecrets, E2eSender, EndpointRx, EndpointTx, Liveness, Offer};
use crate::framing::{MAX_FRAME, MAX_PADDED_PACKET, PAD_BUCKETS, pad, pad_into, read_frame, read_frame_into, unpad, write_frame};
use crate::identity::{ExitKeys, NOISE_PARAMS};
use crate::node::NodeHandle;
use crate::ratelimit::TokenBucket;
use crate::records::MAX_RECORD_ADDRS;

pub const SPLICE_PROTOCOL: StreamProtocol = StreamProtocol::new("/dvpn/splice/2");
pub const EXIT_PROTOCOL: StreamProtocol = StreamProtocol::new("/dvpn/exit/2");

/// Largest IP packet carried through a circuit. Small enough that a full-size packet,
/// padded and sent as a datagram, still fits a DS-Lite (1460) or PPPoE (1492) link
/// unfragmented, with room to spare.
pub const MTU: u16 = 1360;
const _: () = assert!(MTU as usize <= MAX_PADDED_PACKET);
/// IPv4 + UDP headers around a datagram.
const IP_UDP_HEADERS: usize = 28;
const _: () = assert!(PAD_BUCKETS[PAD_BUCKETS.len() - 1] + datagram::OVERHEAD + IP_UDP_HEADERS <= 1452);

/// Followed by the exit's peer ID, so the handshake is bound to the exit the client
/// meant to reach, not just to its key.
const PROLOGUE: &[u8] = b"dvpn-circuit-v2";
const PROTOCOL_VERSION: u8 = 2;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The exit's side of the handshake is shorter: a slot is held while it runs, and an
/// honest client answers within a round trip.
const EXIT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Each direction switches to a new key after this many messages (both sides count the
/// same messages on the ordered stream), so a key exposed later, e.g. by reading an
/// endpoint's memory, decrypts only a window of a long session, not all of it.
pub const REKEY_EVERY: u64 = 1 << 14;
/// Splices a relay runs for one requesting peer at a time.
const MAX_SPLICES_PER_PEER: usize = 8;
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
    /// The client can use a datagram path.
    datagrams: bool,
}

/// The relay's first frame on the exit stream, before the client's handshake.
#[derive(Serialize, Deserialize)]
struct RelayHello {
    datagrams: Option<Offer>,
}

/// The client's first handshake message. Its payload is encrypted only to the exit's
/// static key (`es`): not forward-secret, and an observer can replay it. So it must
/// never carry anything secret or identifying; today it holds only the version.
#[derive(Serialize, Deserialize)]
struct ClientHello {
    version: u8,
}

#[derive(Serialize, Deserialize)]
struct ExitHello {
    assigned_ip: [u8; 4],
    mtu: u16,
    /// Keys for the datagram path: client → exit, exit → client.
    datagram_keys: [[u8; 32]; 2],
}

impl Drop for ExitHello {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.datagram_keys);
    }
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
    /// Keys for a datagram path, until one is attached.
    e2e: Option<(E2eSecrets, Role)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Exit,
}

pub struct TunnelSender {
    writer: WriteHalf<BoxStream>,
    noise: Arc<Mutex<snow::TransportState>>,
    /// Reused for every packet: the padded plaintext, and the frame on the stream.
    plaintext: Vec<u8>,
    frame: Vec<u8>,
    datagrams: Option<Arc<DatagramSender>>,
    _prober: Option<AbortOnDrop>,
    _guard: Option<Guard>,
}

pub struct TunnelReceiver {
    stream: StreamSource,
    noise: Arc<Mutex<snow::TransportState>>,
    /// Reused for every packet: the frame read from the stream, and its plaintext.
    frame: Vec<u8>,
    plaintext: Vec<u8>,
    datagrams: Option<DatagramReceiver>,
    _guard: Option<Guard>,
}

enum StreamSource {
    Direct(ReadHalf<BoxStream>),
    /// Read by a task, so waiting for a frame and for a datagram at once can't lose
    /// half a frame when the datagram wins.
    Task {
        frames: mpsc::Receiver<std::io::Result<Option<Vec<u8>>>>,
        _reader: AbortOnDrop,
    },
    Moving,
}

struct DatagramSender {
    endpoint: EndpointTx,
    e2e: Mutex<E2eSender>,
    liveness: Liveness,
}

impl DatagramSender {
    async fn send(&self, padded: &[u8]) -> std::io::Result<()> {
        let sealed = self.e2e.lock().expect("e2e lock").seal(padded);
        self.endpoint.send(&sealed).await
    }
}

struct DatagramReceiver {
    endpoint: EndpointRx,
    e2e: E2eReceiver,
    liveness: Liveness,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Tunnel {
    /// Sends and receives through `socket` as well, by the relay's `offer`, if the relay
    /// is reachable at `relay`. Returns whether a datagram path was set up; packets use
    /// it once datagrams arrive from the other end.
    pub fn attach_datagrams(&mut self, socket: &Arc<datagram::Socket>, offer: &Offer, relay: Ipv4Addr) -> bool {
        let Some((secrets, role)) = self.e2e.take() else {
            return false;
        };
        let Some((endpoint_tx, endpoint_rx)) = socket.endpoint(offer, relay) else {
            return false;
        };
        let (send_key, recv_key) = match role {
            Role::Client => (&secrets.client_to_exit, &secrets.exit_to_client),
            Role::Exit => (&secrets.exit_to_client, &secrets.client_to_exit),
        };
        let liveness = Liveness::default();
        let sender = Arc::new(DatagramSender {
            endpoint: endpoint_tx,
            e2e: Mutex::new(E2eSender::new(send_key)),
            liveness: liveness.clone(),
        });
        self.rx.datagrams = Some(DatagramReceiver {
            endpoint: endpoint_rx,
            e2e: E2eReceiver::new(recv_key),
            liveness: liveness.clone(),
        });
        if let StreamSource::Direct(mut reader) = std::mem::replace(&mut self.rx.stream, StreamSource::Moving) {
            let (frames_tx, frames_rx) = mpsc::channel(64);
            let task = tokio::spawn(async move {
                loop {
                    let frame = read_frame(&mut reader).await;
                    let last = !matches!(frame, Ok(Some(_)));
                    if frames_tx.send(frame).await.is_err() || last {
                        return;
                    }
                }
            });
            self.rx.stream = StreamSource::Task {
                frames: frames_rx,
                _reader: AbortOnDrop(task),
            };
        }
        let keepalive = pad(&[]).expect("empty packet fits");
        let probing = sender.clone();
        self.tx._prober = Some(AbortOnDrop(tokio::spawn(datagram::probe(liveness, move || {
            let (sender, keepalive) = (probing.clone(), keepalive.clone());
            async move { sender.send(&keepalive).await }
        }))));
        self.tx.datagrams = Some(sender);
        true
    }

    /// Whether packets currently go out as datagrams.
    pub fn uses_datagrams(&self) -> bool {
        self.tx.uses_datagrams()
    }

    /// Tells whether datagrams arrive, for as long as the tunnel lives.
    pub fn datagram_liveness(&self) -> Option<Liveness> {
        self.tx.datagrams.as_ref().map(|d| d.liveness.clone())
    }
}

impl TunnelSender {
    pub async fn send(&mut self, packet: &[u8]) -> Result<(), CircuitError> {
        if packet.len() > MTU as usize {
            return Err(CircuitError::PacketTooLarge);
        }
        if !pad_into(packet, &mut self.plaintext) {
            return Err(CircuitError::PacketTooLarge);
        }
        let plaintext = &self.plaintext;
        if let Some(datagrams) = &self.datagrams
            && datagrams.liveness.alive()
            && datagrams.send(plaintext).await.is_ok()
            // A keepalive after datagrams have been quiet for a while goes over the
            // stream too: if the datagram path just died, the keepalive still gets
            // through, and the circuit survives until packets switch back to the stream.
            && !(packet.is_empty() && datagrams.liveness.quiet_for(KEEPALIVE_INTERVAL))
        {
            return Ok(());
        }
        // Length prefix and ciphertext in one buffer: one write, one frame on the stream.
        let frame = &mut self.frame;
        frame.resize(2 + plaintext.len() + 16, 0);
        let n = {
            let mut noise = self.noise.lock().expect("noise lock");
            let n = noise.write_message(plaintext, &mut frame[2..])?;
            if noise.sending_nonce().is_multiple_of(REKEY_EVERY) {
                noise.rekey_outgoing();
            }
            n
        };
        frame[..2].copy_from_slice(&(n as u16).to_be_bytes());
        self.writer.write_all(&frame[..2 + n]).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), CircuitError> {
        self.writer.close().await?;
        Ok(())
    }

    pub fn uses_datagrams(&self) -> bool {
        self.datagrams.as_ref().is_some_and(|d| d.liveness.alive())
    }
}

enum Incoming {
    Frame(Option<Vec<u8>>),
    Datagram(Vec<u8>),
}

impl TunnelReceiver {
    /// The next packet; `Ok(None)` when the peer closed the tunnel cleanly.
    /// Any frame that fails authentication ends the tunnel with [`CircuitError::Integrity`].
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, CircuitError> {
        let from_task;
        let frame: &[u8] = loop {
            let incoming = match (&mut self.stream, &mut self.datagrams) {
                (StreamSource::Direct(reader), _) => match read_frame_into(reader, &mut self.frame).await? {
                    true => break &self.frame,
                    false => return Ok(None),
                },
                (StreamSource::Task { frames, .. }, Some(datagrams)) => tokio::select! {
                    frame = frames.recv() => Incoming::Frame(frame.unwrap_or(Ok(None))?),
                    Some(datagram) = datagrams.endpoint.recv() => Incoming::Datagram(datagram),
                },
                (StreamSource::Task { frames, .. }, None) => Incoming::Frame(frames.recv().await.unwrap_or(Ok(None))?),
                (StreamSource::Moving, _) => unreachable!("only while attaching"),
            };
            match incoming {
                Incoming::Frame(Some(frame)) => {
                    from_task = frame;
                    break &from_task;
                }
                Incoming::Frame(None) => return Ok(None),
                // Datagrams can be lost, duplicated or forged on the way; anything that
                // doesn't authenticate is dropped, not fatal.
                Incoming::Datagram(sealed) => {
                    let datagrams = self.datagrams.as_mut().expect("datagram received");
                    let Some(padded) = datagrams.e2e.open(&sealed) else { continue };
                    datagrams.liveness.heard();
                    if let Some(packet) = unpad(&padded) {
                        return Ok(Some(packet.to_vec()));
                    }
                }
            }
        };
        let plaintext = &mut self.plaintext;
        plaintext.resize(frame.len(), 0);
        let n = {
            let mut noise = self.noise.lock().expect("noise lock");
            let n = noise.read_message(frame, plaintext).map_err(|_| CircuitError::Integrity)?;
            if noise.receiving_nonce().is_multiple_of(REKEY_EVERY) {
                noise.rekey_incoming();
            }
            n
        };
        let packet = unpad(&plaintext[..n]).ok_or(CircuitError::Integrity)?;
        Ok(Some(packet.to_vec()))
    }
}

fn into_tunnel(
    stream: BoxStream,
    noise: snow::HandshakeState,
    role: Role,
    hello: ExitHello,
    guard: Option<Guard>,
) -> Result<Tunnel, CircuitError> {
    let secrets = E2eSecrets {
        client_to_exit: Zeroizing::new(hello.datagram_keys[0]),
        exit_to_client: Zeroizing::new(hello.datagram_keys[1]),
    };
    let noise = Arc::new(Mutex::new(noise.into_transport_mode()?));
    let (reader, writer) = stream.split();
    Ok(Tunnel {
        assigned_ip: Ipv4Addr::from(hello.assigned_ip),
        mtu: hello.mtu,
        tx: TunnelSender {
            writer,
            noise: noise.clone(),
            plaintext: Vec::new(),
            frame: Vec::new(),
            datagrams: None,
            _prober: None,
            _guard: guard.clone(),
        },
        rx: TunnelReceiver {
            stream: StreamSource::Direct(reader),
            noise,
            frame: Vec::new(),
            plaintext: Vec::new(),
            datagrams: None,
            _guard: guard,
        },
        e2e: Some((secrets, role)),
    })
}

async fn read_handshake_frame(stream: &mut BoxStream) -> Result<Vec<u8>, CircuitError> {
    read_frame(stream)
        .await?
        .ok_or_else(|| CircuitError::Handshake("stream closed during handshake".into()))
}

fn prologue(exit: &PeerId) -> Vec<u8> {
    [PROLOGUE, &exit.to_bytes()].concat()
}

/// Client side of Noise_NK: authenticates `exit` by its static key; sends no identity.
pub async fn client_handshake<S>(stream: S, exit: &PeerId, exit_static: &[u8; 32]) -> Result<Tunnel, CircuitError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let prologue = prologue(exit);
    let mut noise = snow::Builder::new(NOISE_PARAMS.parse()?)
        .remote_public_key(exit_static)?
        .prologue(&prologue)?
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
    into_tunnel(stream, noise, Role::Client, hello, None)
}

/// Exit side of Noise_NK, as exit `local`. `guard` is kept alive for as long as the
/// tunnel exists.
/// Exit side of the handshake. `static_keys` are the keys a client may have from our
/// record ([`crate::identity::ExitKeys::candidates`]), tried in order.
pub async fn exit_handshake<S, K>(
    stream: S,
    local: &PeerId,
    static_keys: &[K],
    assigned_ip: Ipv4Addr,
    guard: Option<Guard>,
) -> Result<Tunnel, CircuitError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    K: AsRef<[u8]>,
{
    let mut stream: BoxStream = Box::new(stream);
    let prologue = prologue(local);
    let mut buf = vec![0u8; MAX_FRAME];

    let first = read_handshake_frame(&mut stream).await?;
    let mut accepted = None;
    for key in static_keys {
        let mut noise = snow::Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(key.as_ref())?
            .prologue(&prologue)?
            .build_responder()?;
        // Only the right key decrypts the first message.
        if let Ok(n) = noise.read_message(&first, &mut buf) {
            accepted = Some((noise, n));
            break;
        }
    }
    let (mut noise, n) = accepted.ok_or_else(|| CircuitError::Handshake("the client used none of our keys".into()))?;
    let hello: ClientHello =
        postcard::from_bytes(&buf[..n]).map_err(|_| CircuitError::Handshake("malformed client hello".into()))?;
    if hello.version != PROTOCOL_VERSION {
        return Err(CircuitError::Handshake(format!("unsupported version {}", hello.version)));
    }

    let keys = E2eSecrets::random();
    let hello = ExitHello {
        assigned_ip: assigned_ip.octets(),
        mtu: MTU,
        datagram_keys: [*keys.client_to_exit, *keys.exit_to_client],
    };
    let payload = postcard::to_stdvec(&hello).expect("serializable");
    let n = noise.write_message(&payload, &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    into_tunnel(stream, noise, Role::Exit, hello, guard)
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

    let socket = handle.datagram_socket();
    let request = SpliceRequest {
        exit: exit.to_bytes(),
        addrs: exit_addrs.iter().take(MAX_RECORD_ADDRS).map(|a| a.to_vec()).collect(),
        datagrams: socket.is_some(),
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
    let offer = timeout(HANDSHAKE_TIMEOUT, read_frame(&mut stream))
        .await
        .map_err(|_| CircuitError::Timeout)??
        .and_then(|frame| postcard::from_bytes::<Option<Offer>>(&frame).ok())
        .ok_or(CircuitError::RelayRefused)?;

    let mut tunnel = timeout(HANDSHAKE_TIMEOUT, client_handshake(stream, &exit, exit_static))
        .await
        .map_err(|_| CircuitError::Timeout)??;
    if let (Some(socket), Some(offer)) = (socket, offer)
        && let Some(ip) = direct_ipv4(handle, relay).await
    {
        tunnel.attach_datagrams(&socket, &offer, ip);
    }
    Ok(tunnel)
}

/// The IPv4 address of a direct (not relayed) connection to `peer`: where its datagram
/// socket is.
async fn direct_ipv4(handle: &NodeHandle, peer: PeerId) -> Option<Ipv4Addr> {
    let connected = handle.connected_addrs(peer).await.ok()?;
    connected.iter().filter(|a| !addrs::is_circuit(a)).find_map(|a| match addrs::ip_of(a) {
        Some(IpAddr::V4(ip)) if !ip.is_unspecified() => Some(ip),
        _ => None,
    })
}

/// Relay: accepts splice requests and pipes them to the requested exit.
pub(crate) async fn serve_splices(
    handle: NodeHandle,
    mut incoming: libp2p_stream::IncomingStreams,
    rate_mbps: u64,
    allow_private: bool,
) {
    let slots = Arc::new(Semaphore::new(MAX_SPLICES));
    // One peer can't take every splice slot.
    let per_peer = RelayQuota::new(MAX_SPLICES_PER_PEER);
    while let Some((from, stream)) = incoming.next().await {
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!("splice limit reached; dropping request");
            continue;
        };
        let Some(ticket) = per_peer.acquire(from) else {
            debug!("too many splices for one peer; dropping request");
            continue;
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let _slot = (slot, ticket);
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
    let mut exit_stream = exit_stream;
    let relayed = match handle.datagram_socket() {
        Some(socket) if request.datagrams => socket.relay(rate_mbps),
        _ => None,
    };
    let (_relaying, client_offer, exit_offer) = match relayed {
        Some((guard, a, b)) => (Some(guard), Some(a), Some(b)),
        None => (None, None, None),
    };
    let hello = postcard::to_stdvec(&RelayHello { datagrams: exit_offer }).expect("serializable");
    write_frame(&mut exit_stream, &hello).await?;
    write_frame(&mut client, &[SPLICE_OK]).await?;
    write_frame(&mut client, &postcard::to_stdvec(&client_offer).expect("serializable")).await?;
    // Datagrams are relayed for as long as the streams are.
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
    handle: NodeHandle,
    mut incoming: libp2p_stream::IncomingStreams,
    local: PeerId,
    keys: Arc<ExitKeys>,
    max_sessions: usize,
    pool: IpPool,
    sessions: mpsc::Sender<ExitSession>,
) {
    let slots = Arc::new(Semaphore::new(max_sessions));
    let per_relay = RelayQuota::new(per_relay_limit(max_sessions));
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
        let keys = keys.candidates();
        let sessions = sessions.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            let ip = lease.ip;
            let guard: Guard = Arc::new((lease, slot, ticket));
            let accept = async {
                let mut stream = stream;
                let hello = read_frame(&mut stream)
                    .await?
                    .and_then(|frame| postcard::from_bytes::<RelayHello>(&frame).ok())
                    .ok_or_else(|| CircuitError::Handshake("malformed relay hello".into()))?;
                let tunnel = exit_handshake(stream, &local, &keys, ip, Some(guard)).await?;
                Ok::<_, CircuitError>((tunnel, hello.datagrams))
            };
            match timeout(EXIT_HANDSHAKE_TIMEOUT, accept).await {
                Ok(Ok((mut tunnel, offer))) => {
                    if let (Some(socket), Some(offer)) = (handle.datagram_socket(), offer)
                        && let Some(relay) = direct_ipv4(&handle, via_peer).await
                    {
                        tunnel.attach_datagrams(&socket, &offer, relay);
                    }
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
/// Half, not less: entry relays are the few dedicated servers, so a tighter share would
/// leave most of an exit's slots unusable in a small network.
fn per_relay_limit(max_sessions: usize) -> usize {
    (max_sessions / 2).max(2)
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
    fn the_first_handshake_message_carries_only_the_version() {
        // See ClientHello: anything added here would be readable by whoever later gets
        // the exit's static key, and replayable. Change this test only with that in mind.
        let hello = postcard::to_stdvec(&ClientHello { version: PROTOCOL_VERSION }).unwrap();
        assert_eq!(hello, [PROTOCOL_VERSION]);
    }

    #[test]
    fn one_relay_cannot_take_every_exit_session() {
        assert_eq!(per_relay_limit(16), 8);
        assert_eq!(per_relay_limit(64), 32);
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
