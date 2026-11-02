//! The libp2p node: transports, discovery (Kademlia, mDNS, bootstrap, peer cache),
//! NAT traversal (AutoNAT, Circuit Relay v2, DCUtR), signed-record publication, and
//! the splice/exit stream protocols.
//!
//! Logging never includes remote peer addresses; only peer IDs at debug level.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::identity::Keypair;
use libp2p::kad::{self, store::MemoryStore, store::RecordStore};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::core::transport::ListenerId;
use libp2p::swarm::{ConnectionId, DialError, NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, autonat, dcutr, identify, mdns, noise, ping, relay, tcp, yamux,
};
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::addrs;
use crate::circuit::{self, CircuitError, EXIT_PROTOCOL, ExitSession, IpPool, SPLICE_PROTOCOL, Tunnel};
use crate::config::split_peer_addr;
use crate::guard;
use crate::identity::Identity;
use crate::peer_cache;
use crate::records::{self, EXIT_PROVIDER_KEY, ExitKind, ExitRecord, RECORD_LIFETIME, RELAY_PROVIDER_KEY};

pub const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/dvpn/kad/1.0.0");
const IDENTIFY_PROTOCOL: &str = "/dvpn/id/1.0.0";
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CACHE_SAVE_INTERVAL: Duration = Duration::from_secs(60);
const PUBLISH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(20 * 60);
const MAX_IDENTIFY_ADDRS: usize = 8;
const MAX_RELAY_RESERVATIONS: usize = 2;
const MAX_EXIT_LOOKUPS: usize = 16;
const MAX_CIRCUIT_ATTEMPTS: usize = 3;
const RELAY_RETRY_AFTER: Duration = Duration::from_secs(30);

/// How the node decides whether it is reachable from the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// Detect with AutoNAT; reserve relay slots if behind NAT.
    Auto,
    /// Known to be publicly reachable (e.g. a server with a public IP).
    Public,
    /// Known to be behind NAT: always reserve relay slots, never serve the DHT.
    Private,
    /// Never reachable and needs no reachability (a pure client, e.g. `dvpn connect`).
    Outbound,
}

impl FromStr for Reachability {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "public" => Ok(Self::Public),
            "private" => Ok(Self::Private),
            "outbound" => Ok(Self::Outbound),
            _ => Err(format!("expected auto, public, private or outbound, got {s}")),
        }
    }
}

pub struct ExitConfig {
    pub max_sessions: usize,
    /// Advertised in the exit record, so clients can prefer dedicated exits.
    pub kind: ExitKind,
    /// Advertised in the exit record; enforced by [`crate::policy::ExitPolicy`].
    pub blocked_tcp_ports: Vec<u16>,
}

pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub listen: Vec<Multiaddr>,
    /// Multiaddrs ending in `/p2p/<peer-id>`.
    pub bootstrap: Vec<Multiaddr>,
    pub mdns: bool,
    pub peer_cache: bool,
    pub reachability: Reachability,
    /// Act as an entry relay (splice) and Circuit Relay v2 server.
    pub relay: bool,
    /// Bandwidth cap per spliced circuit and direction; 0 = unlimited.
    pub relay_rate_mbps: u64,
    /// Accept exit tunnels. Sessions are delivered on [`Node::exit_sessions`].
    pub exit: Option<ExitConfig>,
    /// Treat loopback/private addresses as usable (local testing, LAN-only networks).
    pub allow_private_addrs: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NatState {
    Unknown,
    Public,
    Private,
}

#[derive(Clone, Debug)]
pub struct NodeStatus {
    pub nat: NatState,
    /// Relays currently holding an accepted reservation for us.
    pub relay_reservations: usize,
    pub external_addrs: Vec<Multiaddr>,
    /// Successful DCUtR hole punches since start.
    pub hole_punches: usize,
    /// Reachable without a relay: configured public, or confirmed by AutoNAT.
    pub publicly_reachable: bool,
    /// Our exit record was published and is still valid.
    pub exit_published: bool,
}

/// An open client circuit.
pub struct Circuit {
    pub relay: PeerId,
    pub exit: PeerId,
    pub tunnel: Tunnel,
}

pub struct Node {
    pub handle: NodeHandle,
    pub task: JoinHandle<anyhow::Result<()>>,
    /// Present when [`NodeConfig::exit`] is set.
    pub exit_sessions: Option<mpsc::Receiver<ExitSession>>,
    /// The exit's virtual address pool, when [`NodeConfig::exit`] is set.
    pub exit_pool: Option<IpPool>,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    autonat: autonat::Behaviour,
    relay: Toggle<relay::Behaviour>,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    stream: libp2p_stream::Behaviour,
}

type Reply<T> = oneshot::Sender<T>;

enum Command {
    ListenAddrs(Reply<Vec<Multiaddr>>),
    RoutingPeers(Reply<Vec<PeerId>>),
    PeerAddrs(PeerId, Reply<Vec<Multiaddr>>),
    ConnectedAddrs(PeerId, Reply<Vec<Multiaddr>>),
    Status(Reply<NodeStatus>),
    Dial {
        peer: PeerId,
        addrs: Vec<Multiaddr>,
        force_new: bool,
        reply: Reply<Result<Multiaddr, String>>,
    },
    GetProviders(kad::RecordKey, Reply<HashSet<PeerId>>),
    GetRecords(kad::RecordKey, Reply<Vec<kad::Record>>),
    Shutdown(Reply<()>),
}

/// Cheap, cloneable handle to a running node.
#[derive(Clone)]
pub struct NodeHandle {
    peer_id: PeerId,
    tx: mpsc::Sender<Command>,
    control: libp2p_stream::Control,
    data_dir: PathBuf,
}

impl NodeHandle {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub(crate) fn control(&self) -> libp2p_stream::Control {
        self.control.clone()
    }

    pub async fn listen_addrs(&self) -> anyhow::Result<Vec<Multiaddr>> {
        self.request(Command::ListenAddrs).await
    }

    /// Peers currently in the Kademlia routing table.
    pub async fn routing_peers(&self) -> anyhow::Result<Vec<PeerId>> {
        self.request(Command::RoutingPeers).await
    }

    pub async fn status(&self) -> anyhow::Result<NodeStatus> {
        self.request(Command::Status).await
    }

    /// Dials `peer` and returns the remote address of the new connection.
    /// With `force_new`, a new connection is made even if one already exists.
    pub async fn dial(&self, peer: PeerId, addrs: Vec<Multiaddr>, force_new: bool) -> anyhow::Result<Multiaddr> {
        self.request(|reply| Command::Dial {
            peer,
            addrs,
            force_new,
            reply,
        })
        .await?
        .map_err(|e| anyhow!(e))
    }

    /// Valid, unexpired exit records found in the DHT.
    pub async fn find_exits(&self) -> anyhow::Result<Vec<ExitRecord>> {
        let providers = self.providers(EXIT_PROVIDER_KEY).await?;
        let lookups = providers
            .into_iter()
            .filter(|p| *p != self.peer_id)
            .take(MAX_EXIT_LOOKUPS)
            .map(|peer| async move {
                let records = self.request(|r| Command::GetRecords(records::exit_record_key(&peer), r)).await.ok()?;
                records
                    .iter()
                    .filter_map(|r| ExitRecord::verify(r).ok())
                    .filter(|r| r.peer_id == peer)
                    .max_by_key(|r| r.expires_at)
            });
        Ok(futures::future::join_all(lookups).await.into_iter().flatten().collect())
    }

    /// Peers announcing themselves as entry relays.
    pub async fn find_relays(&self) -> anyhow::Result<Vec<PeerId>> {
        let relays = self.providers(RELAY_PROVIDER_KEY).await?;
        Ok(relays.into_iter().filter(|p| *p != self.peer_id).collect())
    }

    /// Builds a 2-hop circuit: picks an exit from the DHT and an entry relay (the
    /// persisted guard when possible) in a different /16 than the exit.
    pub async fn open_circuit(&self) -> anyhow::Result<Circuit> {
        let exits = self.find_exits().await?;
        let relays = self.find_relays().await?;
        self.open_circuit_from(exits, relays, |_, _| Ok(())).await
    }

    /// Like [`Self::open_circuit`] with known candidates. `prepare` runs before each
    /// attempt with the chosen relay and its known addresses (e.g. to add a route).
    pub async fn open_circuit_from(
        &self,
        mut exits: Vec<ExitRecord>,
        mut relays: Vec<PeerId>,
        mut prepare: impl FnMut(PeerId, &[Multiaddr]) -> anyhow::Result<()>,
    ) -> anyhow::Result<Circuit> {
        if exits.is_empty() {
            bail!("no exits found in the network");
        }
        exits.shuffle(&mut rand::rng());
        relays.shuffle(&mut rand::rng());
        let saved_guard = guard::load(&self.data_dir);

        let mut last_error = anyhow!("no relay satisfies the path constraints");
        for exit in exits.iter().take(MAX_CIRCUIT_ATTEMPTS) {
            let Some((relay, relay_addrs)) = self.choose_relay(saved_guard, &relays, exit).await? else {
                continue;
            };
            if let Err(e) = prepare(relay, &relay_addrs) {
                last_error = e;
                continue;
            }
            match self.open_circuit_via(relay, exit).await {
                Ok(circuit) => {
                    if saved_guard != Some(relay) {
                        guard::save(&self.data_dir, relay)?;
                    }
                    return Ok(circuit);
                }
                Err(e) => {
                    if saved_guard == Some(relay) && matches!(e, CircuitError::RelayRefused) {
                        guard::clear(&self.data_dir);
                    }
                    last_error = e.into();
                }
            }
        }
        Err(last_error)
    }

    /// Builds a circuit through a specific relay to a specific exit.
    pub async fn open_circuit_via(&self, relay: PeerId, exit: &ExitRecord) -> Result<Circuit, CircuitError> {
        let tunnel = circuit::open_via_relay(self, relay, exit.peer_id, &exit.addrs, &exit.noise_static).await?;
        Ok(Circuit {
            relay,
            exit: exit.peer_id,
            tunnel,
        })
    }

    /// Saves the peer cache and stops the node.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.request(Command::Shutdown).await
    }

    async fn choose_relay(
        &self,
        saved_guard: Option<PeerId>,
        relays: &[PeerId],
        exit: &ExitRecord,
    ) -> anyhow::Result<Option<(PeerId, Vec<Multiaddr>)>> {
        for candidate in saved_guard.iter().chain(relays) {
            if *candidate == exit.peer_id || *candidate == self.peer_id {
                continue;
            }
            let relay_addrs = self.peer_addrs(*candidate).await?;
            if !addrs::same_slash16(&relay_addrs, &exit.addrs) {
                return Ok(Some((*candidate, relay_addrs)));
            }
        }
        Ok(None)
    }

    /// Addresses of `peer` in the routing table.
    pub async fn peer_addrs(&self, peer: PeerId) -> anyhow::Result<Vec<Multiaddr>> {
        self.request(|r| Command::PeerAddrs(peer, r)).await
    }

    /// Remote addresses of our open connections to `peer`.
    pub async fn connected_addrs(&self, peer: PeerId) -> anyhow::Result<Vec<Multiaddr>> {
        self.request(|r| Command::ConnectedAddrs(peer, r)).await
    }

    async fn providers(&self, key: &[u8]) -> anyhow::Result<HashSet<PeerId>> {
        self.request(|r| Command::GetProviders(kad::RecordKey::new(&key), r)).await
    }

    async fn request<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> anyhow::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(make(tx)).await.context("node has stopped")?;
        rx.await.context("node has stopped")
    }
}

/// Builds the swarm and runs it on background tasks. Must be called inside a Tokio runtime.
pub fn spawn(identity: Identity, config: NodeConfig) -> anyhow::Result<Node> {
    let peer_id = identity.peer_id();
    let keypair = identity.keypair.clone();
    let noise_public = identity.exit_static.public;
    let exit_private = identity.exit_static.private;
    let mut swarm = build_swarm(identity.keypair, &config)?;

    for addr in &config.listen {
        swarm.listen_on(addr.clone()).with_context(|| format!("cannot listen on {addr}"))?;
    }

    let kad = &mut swarm.behaviour_mut().kad;
    kad.set_mode(match config.reachability {
        Reachability::Public => Some(kad::Mode::Server),
        Reachability::Private | Reachability::Outbound => Some(kad::Mode::Client),
        // Kademlia switches to server mode once AutoNAT confirms an external address.
        Reachability::Auto => None,
    });
    for addr in &config.bootstrap {
        let (peer, transport) = split_peer_addr(addr)?;
        kad.add_address(&peer, transport);
    }
    if config.peer_cache {
        for (peer, addrs) in peer_cache::load(&config.data_dir)? {
            for addr in addrs {
                kad.add_address(&peer, addr);
            }
        }
    }
    // Fails only with an empty routing table; mDNS or later contacts trigger it then.
    let _ = kad.bootstrap();

    let mut control = swarm.behaviour().stream.new_control();
    let (tx, rx) = mpsc::channel(64);
    let handle = NodeHandle {
        peer_id,
        tx,
        control: control.clone(),
        data_dir: config.data_dir.clone(),
    };

    if config.relay {
        let incoming = control.accept(SPLICE_PROTOCOL).map_err(|_| anyhow!("splice protocol already registered"))?;
        tokio::spawn(circuit::serve_splices(
            handle.clone(),
            incoming,
            config.relay_rate_mbps,
            config.allow_private_addrs,
        ));
    }
    let (exit_sessions, exit_pool) = match &config.exit {
        Some(exit) => {
            let incoming = control.accept(EXIT_PROTOCOL).map_err(|_| anyhow!("exit protocol already registered"))?;
            let (sessions_tx, sessions_rx) = mpsc::channel(exit.max_sessions.max(1));
            let pool = IpPool::default();
            tokio::spawn(circuit::serve_exit(incoming, exit_private, exit.max_sessions, pool.clone(), sessions_tx));
            (Some(sessions_rx), Some(pool))
        }
        None => (None, None),
    };

    let driver = Driver {
        swarm,
        config,
        keypair,
        noise_public,
        nat: NatState::Unknown,
        hop_relays: HashMap::new(),
        relay_listeners: HashMap::new(),
        failed_relays: HashMap::new(),
        connections: HashMap::new(),
        hole_punches: 0,
        pending_dials: HashMap::new(),
        pending_providers: HashMap::new(),
        pending_records: HashMap::new(),
        exit_published: None,
        relay_published: None,
    };
    let task = tokio::spawn(driver.run(rx));
    Ok(Node {
        handle,
        task,
        exit_sessions,
        exit_pool,
    })
}

fn build_swarm(keypair: Keypair, config: &NodeConfig) -> anyhow::Result<Swarm<Behaviour>> {
    let enable_mdns = config.mdns;
    let enable_relay = config.relay;
    let allow_private = config.allow_private_addrs;

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(
            |key, relay_client| -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
                let peer_id = key.public().to_peer_id();

                let mut kad_config = kad::Config::new(KAD_PROTOCOL);
                kad_config
                    .disjoint_query_paths(true)
                    // Every insert is validated in `Driver::on_kad_inbound`.
                    .set_record_filtering(kad::StoreInserts::FilterBoth)
                    .set_record_ttl(Some(RECORD_LIFETIME))
                    .set_provider_record_ttl(Some(RECORD_LIFETIME))
                    // We republish fresh, re-signed records ourselves.
                    .set_publication_interval(None)
                    .set_provider_publication_interval(None);
                let kad = kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

                let mdns = if enable_mdns {
                    Some(mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?)
                } else {
                    None
                };

                let autonat = autonat::Behaviour::new(
                    peer_id,
                    autonat::Config {
                        boot_delay: Duration::from_secs(2),
                        retry_interval: Duration::from_secs(10),
                        throttle_server_period: Duration::from_secs(15),
                        only_global_ips: !allow_private,
                        ..Default::default()
                    },
                );

                Ok(Behaviour {
                    kad,
                    identify: identify::Behaviour::new(identify::Config::new(
                        IDENTIFY_PROTOCOL.to_string(),
                        key.public(),
                    )),
                    ping: ping::Behaviour::default(),
                    mdns: Toggle::from(mdns),
                    autonat,
                    relay: Toggle::from(enable_relay.then(|| relay::Behaviour::new(peer_id, relay::Config::default()))),
                    relay_client,
                    dcutr: dcutr::Behaviour::new(peer_id),
                    stream: libp2p_stream::Behaviour::new(),
                })
            },
        )?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();
    Ok(swarm)
}

struct Driver {
    swarm: Swarm<Behaviour>,
    config: NodeConfig,
    keypair: Keypair,
    noise_public: [u8; 32],
    nat: NatState,
    /// Connected peers offering Circuit Relay v2, with a direct address for each.
    hop_relays: HashMap<PeerId, Multiaddr>,
    /// Our relay listeners and whether the reservation was accepted.
    relay_listeners: HashMap<PeerId, (ListenerId, bool)>,
    /// Relays whose reservation failed, and when; retried after [`RELAY_RETRY_AFTER`].
    failed_relays: HashMap<PeerId, Instant>,
    connections: HashMap<PeerId, HashMap<ConnectionId, Multiaddr>>,
    hole_punches: usize,
    pending_dials: HashMap<ConnectionId, Reply<Result<Multiaddr, String>>>,
    pending_providers: HashMap<kad::QueryId, (HashSet<PeerId>, Reply<HashSet<PeerId>>)>,
    pending_records: HashMap<kad::QueryId, (Vec<kad::Record>, Reply<Vec<kad::Record>>)>,
    exit_published: Option<(Instant, Vec<Multiaddr>)>,
    relay_published: Option<Instant>,
}

impl Driver {
    async fn run(mut self, mut rx: mpsc::Receiver<Command>) -> anyhow::Result<()> {
        let mut cache_timer = tokio::time::interval(CACHE_SAVE_INTERVAL);
        let mut publish_timer = tokio::time::interval(PUBLISH_CHECK_INTERVAL);
        cache_timer.tick().await;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.on_event(event),
                command = rx.recv() => match command {
                    Some(Command::Shutdown(reply)) => {
                        self.save_cache();
                        let _ = reply.send(());
                        return Ok(());
                    }
                    Some(command) => self.on_command(command),
                    None => {
                        self.save_cache();
                        return Ok(());
                    }
                },
                _ = publish_timer.tick() => {
                    self.reserve_relays();
                    self.publish();
                }
                _ = cache_timer.tick() => self.save_cache(),
            }
        }
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::ListenAddrs(reply) => {
                let _ = reply.send(self.swarm.listeners().cloned().collect());
            }
            Command::RoutingPeers(reply) => {
                let _ = reply.send(self.routing_table().into_iter().map(|(p, _)| p).collect());
            }
            Command::PeerAddrs(peer, reply) => {
                let addrs = self.routing_table().into_iter().find(|(p, _)| *p == peer).map(|(_, a)| a);
                let _ = reply.send(addrs.unwrap_or_default());
            }
            Command::ConnectedAddrs(peer, reply) => {
                let addrs = self.connections.get(&peer).map(|c| c.values().cloned().collect());
                let _ = reply.send(addrs.unwrap_or_default());
            }
            Command::Status(reply) => {
                let _ = reply.send(NodeStatus {
                    nat: self.nat,
                    relay_reservations: self.relay_listeners.values().filter(|(_, ok)| *ok).count(),
                    external_addrs: self.swarm.external_addresses().cloned().collect(),
                    hole_punches: self.hole_punches,
                    publicly_reachable: self.reachable_publicly(),
                    exit_published: self
                        .exit_published
                        .as_ref()
                        .is_some_and(|(at, _)| at.elapsed() < RECORD_LIFETIME),
                });
            }
            Command::Dial {
                peer,
                addrs,
                force_new,
                reply,
            } => {
                let condition = if force_new {
                    PeerCondition::Always
                } else {
                    PeerCondition::DisconnectedAndNotDialing
                };
                let opts = DialOpts::peer_id(peer).addresses(addrs).condition(condition).build();
                let id = opts.connection_id();
                match self.swarm.dial(opts) {
                    Ok(()) => {
                        self.pending_dials.insert(id, reply);
                    }
                    Err(DialError::DialPeerConditionFalse(_)) => {
                        let _ = reply.send(Err("already connected or dialing".into()));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(addrs::redact(&e.to_string())));
                    }
                }
            }
            Command::GetProviders(key, reply) => {
                let id = self.swarm.behaviour_mut().kad.get_providers(key);
                self.pending_providers.insert(id, (HashSet::new(), reply));
            }
            Command::GetRecords(key, reply) => {
                let id = self.swarm.behaviour_mut().kad.get_record(key);
                self.pending_records.insert(id, (Vec::new(), reply));
            }
            Command::Shutdown(_) => unreachable!("handled in run"),
        }
    }

    fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                // Our own addresses are fine to show; a relay circuit address contains
                // the relay's IP, which is redacted. Circuit addresses already end in /p2p/<us>.
                if addrs::is_circuit(&address) {
                    info!("listening on {}", addrs::redact(&address.to_string()));
                } else {
                    info!("listening on {address}/p2p/{}", self.swarm.local_peer_id());
                }
                // The operator declared this node reachable, so its usable listen
                // addresses are external addresses (this also enables the relay server).
                if self.config.reachability == Reachability::Public
                    && !addrs::is_circuit(&address)
                    && (self.config.allow_private_addrs || addrs::is_public(&address))
                {
                    self.swarm.add_external_address(address);
                }
            }
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                let closed: Vec<PeerId> = self
                    .relay_listeners
                    .iter()
                    .filter(|(_, (id, _))| *id == listener_id)
                    .map(|(p, _)| *p)
                    .collect();
                for relay in closed {
                    if let Some((_, false)) = self.relay_listeners.remove(&relay) {
                        self.failed_relays.insert(relay, Instant::now());
                    }
                }
                self.reserve_relays();
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let addr = match endpoint {
                    ConnectedPoint::Dialer { address, .. } => address,
                    ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
                };
                self.connections.entry(peer_id).or_default().insert(connection_id, addr.clone());
                if let Some(reply) = self.pending_dials.remove(&connection_id) {
                    let _ = reply.send(Ok(addr));
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id, connection_id, ..
            } => {
                if let Some(conns) = self.connections.get_mut(&peer_id) {
                    conns.remove(&connection_id);
                    if conns.is_empty() {
                        self.connections.remove(&peer_id);
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id, error, ..
            } => {
                if let Some(reply) = self.pending_dials.remove(&connection_id) {
                    let _ = reply.send(Err(addrs::redact(&error.to_string())));
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                if info.protocols.contains(&KAD_PROTOCOL) {
                    // A peer chooses what it advertises; loopback or LAN addresses would
                    // make others dial their own machines and networks.
                    let allow_private = self.config.allow_private_addrs;
                    let usable = info.listen_addrs.iter().filter(|a| addrs::is_dialable_for_others(a, allow_private));
                    for addr in usable.take(MAX_IDENTIFY_ADDRS) {
                        self.swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }
                }
                if info.protocols.contains(&relay::HOP_PROTOCOL_NAME) {
                    let direct = info
                        .listen_addrs
                        .iter()
                        .find(|a| !addrs::is_circuit(a) && (self.config.allow_private_addrs || addrs::is_public(a)));
                    if let Some(addr) = direct {
                        // Some listen addresses already end in /p2p/<relay>; we append it ourselves.
                        let mut addr = addr.clone();
                        if let Some(Protocol::P2p(_)) = addr.iter().last() {
                            addr.pop();
                        }
                        self.hop_relays.insert(peer_id, addr);
                        self.reserve_relays();
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
                let kad = &mut self.swarm.behaviour_mut().kad;
                for (peer_id, addr) in found {
                    debug!(%peer_id, "discovered via mDNS");
                    kad.add_address(&peer_id, addr);
                }
                let _ = kad.bootstrap();
            }
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. })) => {
                self.nat = match new {
                    autonat::NatStatus::Public(_) => NatState::Public,
                    autonat::NatStatus::Private => NatState::Private,
                    autonat::NatStatus::Unknown => NatState::Unknown,
                };
                info!("reachability: {:?}", self.nat);
                if self.nat == NatState::Public && self.config.reachability == Reachability::Auto {
                    for (_, (id, _)) in self.relay_listeners.drain() {
                        self.swarm.remove_listener(id);
                    }
                }
                self.reserve_relays();
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                ..
            })) => {
                if let Some(entry) = self.relay_listeners.get_mut(&relay_peer_id) {
                    entry.1 = true;
                }
                info!(relay = %relay_peer_id, "reachable through relay");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                if event.result.is_ok() {
                    self.hole_punches += 1;
                }
                info!(peer_id = %event.remote_peer_id, ok = event.result.is_ok(), "hole punch attempt");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(event)) => self.on_kad(event),
            _ => {}
        }
    }

    fn on_kad(&mut self, event: kad::Event) {
        match event {
            kad::Event::InboundRequest {
                request: kad::InboundRequest::PutRecord {
                    record: Some(record), ..
                },
            } => self.store_record(record),
            kad::Event::InboundRequest {
                request: kad::InboundRequest::AddProvider { record: Some(record) },
            } => {
                if records::is_known_provider_key(&record) {
                    let _ = self.swarm.behaviour_mut().kad.store_mut().add_provider(record);
                }
            }
            kad::Event::RoutingUpdated {
                peer, is_new_peer: true, ..
            } => {
                debug!(peer_id = %peer, "added to routing table");
            }
            kad::Event::OutboundQueryProgressed { id, result, step, .. } => match result {
                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })) => {
                    if let Some((found, _)) = self.pending_providers.get_mut(&id) {
                        found.extend(providers);
                    }
                    if step.last {
                        self.finish_providers(id);
                    }
                }
                kad::QueryResult::GetProviders(_) => self.finish_providers(id),
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(found))) => {
                    if let Some((records, _)) = self.pending_records.get_mut(&id) {
                        records.push(found.record);
                    }
                    if step.last {
                        self.finish_records(id);
                    }
                }
                kad::QueryResult::GetRecord(_) => self.finish_records(id),
                kad::QueryResult::Bootstrap(Err(e)) => debug!("bootstrap step failed: {e:?}"),
                _ => {}
            },
            _ => {}
        }
    }

    fn finish_providers(&mut self, id: kad::QueryId) {
        if let Some((found, reply)) = self.pending_providers.remove(&id) {
            let _ = reply.send(found);
        }
    }

    fn finish_records(&mut self, id: kad::QueryId) {
        if let Some((found, reply)) = self.pending_records.remove(&id) {
            let _ = reply.send(found);
        }
    }

    /// Stores an inbound record only if it is a valid exit record newer than ours.
    fn store_record(&mut self, mut record: kad::Record) {
        let incoming = match ExitRecord::verify(&record) {
            Ok(r) => r,
            Err(e) => {
                debug!("rejected DHT record: {e}");
                return;
            }
        };
        let store = self.swarm.behaviour_mut().kad.store_mut();
        if let Some(existing) = store.get(&record.key).and_then(|r| ExitRecord::verify(&r).ok())
            && existing.expires_at >= incoming.expires_at
        {
            return;
        }
        let remaining = incoming.expires_at.saturating_sub(records::now_secs());
        record.expires = Some(Instant::now() + Duration::from_secs(remaining));
        record.publisher = Some(incoming.peer_id);
        let _ = store.put(record);
    }

    fn reachable_publicly(&self) -> bool {
        match self.config.reachability {
            Reachability::Public => true,
            Reachability::Private | Reachability::Outbound => false,
            Reachability::Auto => self.nat == NatState::Public,
        }
    }

    /// Reserves relay slots while we are (or are configured as) behind NAT.
    fn reserve_relays(&mut self) {
        let wanted = match self.config.reachability {
            Reachability::Private => true,
            Reachability::Public | Reachability::Outbound => false,
            Reachability::Auto => self.nat == NatState::Private,
        };
        if !wanted {
            return;
        }
        let candidates: Vec<(PeerId, Multiaddr)> = self
            .hop_relays
            .iter()
            .filter(|(p, _)| {
                !self.relay_listeners.contains_key(p)
                    && self.failed_relays.get(p).is_none_or(|at| at.elapsed() >= RELAY_RETRY_AFTER)
            })
            .map(|(p, a)| (*p, a.clone()))
            .collect();
        for (relay, addr) in candidates {
            if self.relay_listeners.len() >= MAX_RELAY_RESERVATIONS {
                break;
            }
            let circuit_addr = addr.with(Protocol::P2p(relay)).with(Protocol::P2pCircuit);
            match self.swarm.listen_on(circuit_addr) {
                Ok(id) => {
                    self.relay_listeners.insert(relay, (id, false));
                }
                Err(e) => {
                    debug!(relay = %relay, "relay listen failed: {}", addrs::redact(&e.to_string()));
                    self.failed_relays.insert(relay, Instant::now());
                }
            }
        }
    }

    /// Addresses others can use to reach us: relay circuits, confirmed external
    /// addresses, and public listen addresses when we know we are reachable.
    fn advertised_addrs(&self) -> Vec<Multiaddr> {
        let local = *self.swarm.local_peer_id();
        let external = self.swarm.external_addresses().map(|a| (a, true));
        let listening = self.swarm.listeners().map(|a| (a, false));
        let mut out: Vec<Multiaddr> = Vec::new();
        for (addr, confirmed) in external.chain(listening) {
            let mut addr = addr.clone();
            if let Some(Protocol::P2p(id)) = addr.iter().last()
                && id == local
            {
                addr.pop();
            }
            let usable = addrs::is_circuit(&addr)
                || self.config.allow_private_addrs
                || (addrs::is_public(&addr) && (confirmed || self.reachable_publicly()));
            if usable && !addrs::is_unspecified(&addr) && !out.contains(&addr) {
                out.push(addr);
            }
        }
        out.truncate(records::MAX_RECORD_ADDRS);
        out
    }

    /// Publishes (and periodically refreshes) our exit record and provider entries.
    fn publish(&mut self) {
        if self.routing_table().is_empty() {
            return;
        }
        let now = Instant::now();

        if let Some(exit) = &self.config.exit {
            let blocked_tcp_ports = exit.blocked_tcp_ports.clone();
            let kind = exit.kind;
            let addrs = self.advertised_addrs();
            let due = match &self.exit_published {
                None => true,
                Some((at, published)) => now.duration_since(*at) >= REPUBLISH_INTERVAL || *published != addrs,
            };
            if due && !addrs.is_empty() {
                let record = ExitRecord {
                    peer_id: *self.swarm.local_peer_id(),
                    noise_static: self.noise_public,
                    addrs: addrs.clone(),
                    blocked_tcp_ports,
                    kind,
                    expires_at: records::now_secs() + RECORD_LIFETIME.as_secs(),
                };
                match record.sign(&self.keypair) {
                    Ok(signed) => {
                        let kad = &mut self.swarm.behaviour_mut().kad;
                        let _ = kad.put_record(signed, kad::Quorum::One);
                        let _ = kad.start_providing(kad::RecordKey::new(&EXIT_PROVIDER_KEY));
                        self.exit_published = Some((now, addrs));
                        info!("published exit record");
                    }
                    Err(e) => warn!("could not sign exit record: {e:#}"),
                }
            }
        }

        if self.config.relay && self.reachable_publicly() {
            let due = self.relay_published.is_none_or(|at| now.duration_since(at) >= REPUBLISH_INTERVAL);
            if due {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .start_providing(kad::RecordKey::new(&RELAY_PROVIDER_KEY));
                self.relay_published = Some(now);
                info!("announced as relay");
            }
        }
    }

    fn routing_table(&mut self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        let mut peers = Vec::new();
        for bucket in self.swarm.behaviour_mut().kad.kbuckets() {
            for entry in bucket.iter() {
                peers.push((*entry.node.key.preimage(), entry.node.value.iter().cloned().collect()));
            }
        }
        peers
    }

    fn save_cache(&mut self) {
        if !self.config.peer_cache {
            return;
        }
        let peers = self.routing_table();
        if peers.is_empty() {
            return;
        }
        if let Err(e) = peer_cache::save(&self.config.data_dir, &peers) {
            warn!("could not save peer cache: {e:#}");
        }
    }
}
