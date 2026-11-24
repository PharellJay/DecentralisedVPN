//! Lending: this machine acting as an exit. `dvpn run --exit` lends on its own;
//! `dvpn connect` requires it (see docs/DESIGN.md §3.9).
//!
//! [`Lending::start`] brings up the exit TUN device and the forwarder, then the system
//! changes an exit needs ([`ExitNetwork`]: forwarding, NAT, a firewall that confines
//! clients, and routing that keeps lent traffic out of our own tunnel). Dropping
//! [`Lending`] undoes all of it.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::circuit::{ExitSession, IpPool, MTU};
use crate::device::TunDevice;
use crate::exit::{self, EXIT_TUN_ADDR, EXIT_TUN_PREFIX, ExitOptions};
use crate::node::{NatState, NodeHandle, NodeStatus};
use crate::policy::{ExitPolicy, Ports, SelfAddrs};
use crate::platform::{self, exit::ExitNetwork, net};

pub const EXIT_TUN: &str = "dvpn-exit";
/// The exit's client address pool.
pub const POOL: &str = "10.77.0.0/16";
/// How often lending checks whether this machine changed networks.
const NETWORK_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// A changed public address (see [`LendingHandle::public_ip_changed`]) restarts lending
/// at most this often, so a router that alternates between uplinks can't keep the
/// service restarting.
const MIN_SESSION_AGE_FOR_ROTATION: Duration = Duration::from_secs(30 * 60);

/// Shown before lending is enabled for the first time. Calm, but every sentence must
/// stay true for the actual exit policy (docs/DESIGN.md §3.6).
pub const LENDING_WARNING: &str = "\
Other users' traffic leaves the internet through your connection, just as yours leaves
through theirs. dvpn prefers dedicated exits and only sends others through you when
none of those suits them.

dvpn lends while you're connected, or when you choose to lend. The dvpn service, which
the app uses, also lends from every start of this computer, even when you aren't
connected. To stop that, untick \"Start lending when this computer starts\" in the app.

Your exit only carries common services (the web, email, chat, SSH and the like), so
file sharing, sending spam and scanning don't go through it. It never lets anyone reach
your home network or this computer. dvpn keeps no logs of what passes through.

If someone misuses your connection, complaints may reach you first, because it's your
IP address. Some internet providers' terms don't allow sharing your connection.";
const CONSENT_FILE: &str = "exit-risk-accepted";

/// Whether the user has accepted [`LENDING_WARNING`] for this data directory.
pub fn consent_given(data_dir: &Path) -> bool {
    data_dir.join(CONSENT_FILE).exists()
}

pub fn record_consent(data_dir: &Path) -> anyhow::Result<()> {
    Ok(crate::identity::write_private(&data_dir.join(CONSENT_FILE), b"accepted\n")?)
}

pub struct LendOptions {
    /// Internet-facing interface; `None` uses the default route's device.
    pub wan: Option<String>,
    /// Destinations refused on top of the default policy and this host's own networks.
    pub extra_deny: Vec<Ipv4Net>,
    /// What clients may reach: [`Ports::Reduced`] for users' exits.
    pub ports: Ports,
    /// Per session and direction; 0 = unlimited.
    pub rate_mbps: u64,
    pub max_sessions: usize,
    /// The node's listen addresses; replies from their ports bypass our own tunnel.
    pub listen: Vec<Multiaddr>,
    /// Queues of the exit TUN device, each read by its own task (see
    /// [`TunDevice::create_queues`]): more for busy dedicated exits.
    pub tun_queues: usize,
}

/// What other parts of the program need to know about lending, cheaply cloneable.
#[derive(Clone)]
pub struct LendingHandle {
    /// Active exit sessions.
    pub active: Arc<AtomicUsize>,
    pub max_sessions: usize,
    /// False once the forwarder has stopped.
    pub alive: Arc<AtomicBool>,
    /// The exit's address pool, so our own tunnel address is never leased locally.
    pub pool: IpPool,
    pub wan: String,
    pub rate_mbps: u64,
    /// The exit's own public addresses, refused as destinations.
    pub self_addrs: SelfAddrs,
    /// Set when the default route or this host's networks changed since lending
    /// started: the firewall, the policy and the bypass table are then stale, so
    /// lending must be restarted (the service does that by itself).
    pub network_changed: Arc<AtomicBool>,
    /// Set when peers agree this network's public address changed (an internet
    /// provider assigning a new one, with nothing changing on this host).
    pub public_ip_changed: Arc<AtomicBool>,
    pub started: Instant,
}

impl LendingHandle {
    pub fn ready(&self, status: &NodeStatus) -> bool {
        lending_ready(status, self.alive.load(Ordering::Relaxed) && !self.network_changed())
    }

    pub fn network_changed(&self) -> bool {
        self.network_changed.load(Ordering::Relaxed)
    }

    /// The public address changed and this session is old enough to be replaced: the
    /// service then starts a new one, with a new identity, so peers can't link the old
    /// address to the new one through this node's ID.
    pub fn public_ip_changed(&self) -> bool {
        self.public_ip_changed.load(Ordering::Relaxed) && self.started.elapsed() >= MIN_SESSION_AGE_FOR_ROTATION
    }

    /// Refuses `ip` (an address peers see this machine at) as a destination, in the
    /// exit policy and in the firewall. Runs `nft`, so call it off the async threads.
    pub fn add_self_addr(&self, ip: Ipv4Addr) {
        if !crate::addrs::is_public_v4(ip) || !self.self_addrs.add(ip) {
            return;
        }
        if let Err(e) = platform::exit::deny_destination(ip) {
            warn!("could not add this exit's public address to the firewall: {e:#}");
        }
    }
}

/// Lending is ready when others can actually use our exit: the forwarder runs, the exit
/// record is published, and we're reachable directly or through a relay reservation.
pub fn lending_ready(status: &NodeStatus, forwarder_alive: bool) -> bool {
    let reachable = status.publicly_reachable || status.nat == NatState::Public || status.relay_reservations > 0;
    forwarder_alive && status.exit_published && reachable
}

pub struct Lending {
    handle: LendingHandle,
    forwarder: JoinHandle<()>,
    watcher: JoinHandle<()>,
    _system: ExitNetwork,
}

impl Lending {
    /// Starts lending. `sessions` and `pool` come from a node spawned with an exit config.
    pub fn start(sessions: mpsc::Receiver<ExitSession>, pool: IpPool, options: LendOptions) -> anyhow::Result<Self> {
        // Checked before anything changes on the system.
        let original_default = net::default_route()?.context("no default route; lending needs an internet connection")?;
        let wan = options.wan.clone().unwrap_or_else(|| original_default.dev.clone());
        if !platform::valid_interface_name(&wan) {
            bail!("invalid WAN interface name {wan:?}");
        }
        let queues: Vec<Arc<TunDevice>> = TunDevice::create_queues(EXIT_TUN, EXIT_TUN_ADDR, EXIT_TUN_PREFIX, MTU, options.tun_queues)
            .context("creating the exit TUN device")?
            .into_iter()
            .map(Arc::new)
            .collect();

        // Never let clients reach this host or the networks it's attached to.
        let network = NetworkSnapshot::current()?;
        let mut deny = network.local_networks.clone();
        deny.extend(options.extra_deny);
        let policy = ExitPolicy::new(deny, options.ports.clone());
        let self_addrs = policy.self_addrs.clone();
        let exit_options = Arc::new(ExitOptions {
            policy,
            rate_mbps: options.rate_mbps,
        });

        let system = ExitNetwork::install(&wan, &options.ports, &original_default, &listen_ports(&options.listen))?;

        let active = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let forwarder = tokio::spawn({
            let (active, alive) = (active.clone(), alive.clone());
            async move {
                exit::forward_queues(queues, sessions, exit_options, active).await;
                alive.store(false, Ordering::Relaxed);
                warn!("exit forwarder stopped; lending is down");
            }
        });
        let network_changed = Arc::new(AtomicBool::new(false));
        let watcher = tokio::spawn(watch_network(network, network_changed.clone()));
        info!(wan = %wan, "lending: exit enabled on {EXIT_TUN} ({EXIT_TUN_ADDR}/{EXIT_TUN_PREFIX})");
        Ok(Self {
            handle: LendingHandle {
                active,
                max_sessions: options.max_sessions,
                alive,
                pool,
                wan,
                rate_mbps: options.rate_mbps,
                self_addrs,
                network_changed,
                public_ip_changed: Arc::new(AtomicBool::new(false)),
                started: Instant::now(),
            },
            forwarder,
            watcher,
            _system: system,
        })
    }

    pub fn handle(&self) -> LendingHandle {
        self.handle.clone()
    }
}

impl Drop for Lending {
    fn drop(&mut self) {
        // Stop forwarding before the firewall and routes go away.
        self.forwarder.abort();
        self.watcher.abort();
    }
}

/// Keeps feeding the addresses peers see this machine at into the exit's deny list (see
/// [`crate::policy::SelfAddrs`]) until the node stops.
pub fn watch_own_addresses(handle: NodeHandle, lending: LendingHandle) {
    tokio::spawn(async move {
        let mut first_confirmed = None;
        loop {
            let Ok(status) = handle.status().await else {
                return;
            };
            if let Some(ip) = status.confirmed_public_ip {
                let first = *first_confirmed.get_or_insert(ip);
                if ip != first && !lending.public_ip_changed.swap(true, Ordering::Relaxed) {
                    info!("this network's public address changed");
                }
            }
            let ips: Vec<Ipv4Addr> = status
                .external_addrs
                .iter()
                // A relay-circuit address carries the relay's IP, not ours.
                .filter(|addr| !crate::addrs::is_circuit(addr))
                .filter_map(crate::addrs::ip_of)
                .filter_map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .chain(status.observed_addrs.iter().copied())
                .collect();
            let lending = lending.clone();
            let _ = tokio::task::spawn_blocking(move || ips.into_iter().for_each(|ip| lending.add_self_addr(ip))).await;
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}

/// What lending's firewall, policy and bypass table were built from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkSnapshot {
    default_route: Option<net::NextHop>,
    /// This host's networks, without dvpn's own virtual ones.
    local_networks: Vec<Ipv4Net>,
}

impl NetworkSnapshot {
    fn current() -> anyhow::Result<Self> {
        let pool: Ipv4Net = POOL.parse().expect("valid pool");
        let mut local_networks: Vec<Ipv4Net> = net::local_ipv4_networks()?
            .into_iter()
            .filter(|net| !pool.contains(net))
            .collect();
        local_networks.sort();
        local_networks.dedup();
        Ok(Self {
            default_route: net::default_route()?,
            local_networks,
        })
    }
}

/// Sets `changed` once this machine's default route or networks differ from `start`
/// (e.g. it moved from cable to Wi-Fi). Lending built for the old network would drop
/// lent traffic (the firewall names the old WAN interface) or let clients reach the new
/// LAN if its addresses are public, so it must be rebuilt.
async fn watch_network(start: NetworkSnapshot, changed: Arc<AtomicBool>) {
    loop {
        tokio::time::sleep(NETWORK_CHECK_INTERVAL).await;
        let Ok(Ok(now)) = tokio::task::spawn_blocking(NetworkSnapshot::current).await else {
            continue;
        };
        if now != start {
            warn!("this machine changed networks; lending must restart for the new one");
            changed.store(true, Ordering::Relaxed);
            return;
        }
    }
}

/// TCP and UDP ports the node listens on.
pub fn listen_ports(listen: &[Multiaddr]) -> Vec<(&'static str, u16)> {
    let mut ports = Vec::new();
    for addr in listen {
        let port = addr.iter().find_map(|p| match p {
            Protocol::Tcp(port) => Some(("tcp", port)),
            Protocol::Udp(port) => Some(("udp", port)),
            _ => None,
        });
        if let Some(port) = port
            && port.1 != 0
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(nat: NatState, reservations: usize, published: bool, public: bool) -> NodeStatus {
        NodeStatus {
            nat,
            relay_reservations: reservations,
            external_addrs: vec![],
            hole_punches: 0,
            publicly_reachable: public,
            exit_published: published,
            observed_addrs: vec![],
            confirmed_public_ip: None,
        }
    }

    #[test]
    fn lending_is_ready_only_when_usable_by_others() {
        // Reachable directly, through AutoNAT, or through a relay; published; forwarding.
        assert!(lending_ready(&status(NatState::Unknown, 0, true, true), true));
        assert!(lending_ready(&status(NatState::Public, 0, true, false), true));
        assert!(lending_ready(&status(NatState::Private, 1, true, false), true));

        assert!(!lending_ready(&status(NatState::Public, 0, false, true), true), "record not published");
        assert!(!lending_ready(&status(NatState::Public, 0, true, true), false), "forwarder stopped");
        assert!(!lending_ready(&status(NatState::Private, 0, true, false), true), "unreachable behind NAT");
        assert!(!lending_ready(&status(NatState::Unknown, 0, true, false), true), "reachability unknown");
    }

    #[test]
    fn finds_listen_ports() {
        let listen: Vec<Multiaddr> = ["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic-v1", "/ip6/::/tcp/4001", "/ip4/0.0.0.0/tcp/0"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(listen_ports(&listen), [("tcp", 4001), ("udp", 4001)]);
    }
}
