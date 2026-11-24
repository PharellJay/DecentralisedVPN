//! Finding a first peer without a server of our own (DESIGN.md §3.2): dvpn nodes meet on
//! the BitTorrent Mainline DHT, a public DHT that millions of BitTorrent clients keep
//! running.
//!
//! - **Searching.** A node with an empty routing table (no peer cache, bootstrap peer or
//!   invite link worked) looks up today's and yesterday's rendezvous keys and dials what
//!   it finds, without a peer ID. From there dvpn's own Kademlia DHT takes over.
//! - **Announcing.** Only lending nodes announce, and only when others can reach them
//!   directly. Their IP is already public in dvpn's exit records, so announcing adds
//!   no new exposure. A user's node also checks that the DHT sees its real IP and not
//!   its exit's, which it would while connected.
//!
//! The keys are opaque hashes, not torrents. They change every day and are spread over
//! [`SHARDS`], so whoever wants to answer every lookup with only their own nodes has to
//! place nodes next to each key again every day. Each search or announcement runs as a
//! short-lived DHT client with a fresh ID: it never stays long enough to start serving
//! the DHT (Mainline's adaptive mode switches after 15 minutes) and never stores
//! strangers' torrents.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use blake2::{Blake2s256, Digest};
use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use mainline::async_dht::AsyncDht;
use mainline::{Dht, Id};
use rand::seq::SliceRandom;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::addrs;
use crate::node::{NatState, NodeHandle, NodeStatus};
use crate::records::{self, ExitKind};

/// Rendezvous keys per day. Announcers use one, searchers look up all of them.
pub const SHARDS: u8 = 4;
/// Peers stored in the Mainline DHT expire after about 30 minutes.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// When announcing isn't possible yet (not reachable, or not sure of our IP).
const ANNOUNCE_RECHECK: Duration = Duration::from_secs(5 * 60);
const ANNOUNCE_RETRY: Duration = Duration::from_secs(2 * 60);
const SEARCH_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
/// For joining the DHT, and for each lookup or announcement.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Peers dialled per search.
const MAX_DIALS: usize = 16;
const POLL: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct RendezvousConfig {
    /// Mainline bootstrap nodes (`host:port`); `None` uses the library's public ones.
    pub mainline_bootstrap: Option<Vec<String>>,
    /// Local address for the DHT's UDP socket; `None` binds to all.
    pub bind: Option<Ipv4Addr>,
    /// How long a node without peers waits for its cache and bootstrap peers first.
    pub search_after: Duration,
    /// Wait before searching again after finding nobody; doubles up to 5 minutes.
    pub search_retry: Duration,
}

impl Default for RendezvousConfig {
    fn default() -> Self {
        Self {
            mainline_bootstrap: None,
            bind: None,
            search_after: Duration::from_secs(10),
            search_retry: Duration::from_secs(30),
        }
    }
}

/// The key for `shard` on `day` (days since the Unix epoch, UTC).
pub fn key(shard: u8, day: u64) -> Id {
    let hash = Blake2s256::new_with_prefix(format!("dvpn/rendezvous/v1/{shard}/{day}")).finalize();
    Id::from_bytes(&hash[..20]).expect("20 bytes")
}

/// Today's and yesterday's keys: a node that announced just before midnight UTC is
/// still found just after it.
pub fn search_keys(day: u64) -> Vec<Id> {
    [day, day.saturating_sub(1)]
        .into_iter()
        .flat_map(|d| (0..SHARDS).map(move |s| key(s, d)))
        .collect()
}

fn today() -> u64 {
    records::now_secs() / 86_400
}

/// Addresses worth dialling from what a search found: each IP once, never ourselves
/// (`own`), public unless `allow_private`, at most [`MAX_DIALS`] of them picked at
/// random. Each becomes a TCP and a QUIC address on the announced port.
pub fn candidates(found: impl IntoIterator<Item = SocketAddrV4>, own: &[SocketAddrV4], allow_private: bool) -> Vec<Multiaddr> {
    let mut seen = HashSet::new();
    let mut peers: Vec<SocketAddrV4> = found
        .into_iter()
        .filter(|a| a.port() != 0 && !own.contains(a))
        .filter(|a| allow_private || addrs::is_public_v4(*a.ip()))
        .filter(|a| seen.insert(*a.ip()))
        .collect();
    peers.shuffle(&mut rand::rng());
    peers
        .into_iter()
        .take(MAX_DIALS)
        .flat_map(|a| {
            let ip = Multiaddr::empty().with(Protocol::Ip4(*a.ip()));
            [
                ip.clone().with(Protocol::Tcp(a.port())),
                ip.with(Protocol::Udp(a.port())).with(Protocol::QuicV1),
            ]
        })
        .collect()
}

/// What decides whether a node may announce itself.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    /// `Some` while the node lends its connection as an exit.
    pub lending: Option<ExitKind>,
    pub publicly_reachable: bool,
    pub nat: Option<NatState>,
    /// The IP the Mainline DHT sees us at.
    pub seen_ip: Option<Ipv4Addr>,
    /// Public IPv4 addresses of our own network interfaces.
    pub interface_ips: Vec<Ipv4Addr>,
    /// The public IP at least two dvpn peers agree they see us at.
    pub confirmed_ip: Option<Ipv4Addr>,
}

/// Announce only from lending nodes others can reach directly, at their real IP.
pub fn should_announce(f: &Facts) -> bool {
    let Some(kind) = f.lending else {
        return false;
    };
    // The DHT sees an address of our own interface: no NAT, and not through a tunnel.
    let direct = f.seen_ip.is_some_and(|ip| f.interface_ips.contains(&ip));
    // A node alone in the network has nobody to confirm it's reachable (AutoNAT), but
    // with the public address on its own interface it most likely is.
    let reachable = f.publicly_reachable || (f.nat != Some(NatState::Private) && direct);
    // A dedicated exit (`run --exit`) never routes its own traffic through a tunnel. A
    // user's node does while connected, and the DHT would then see its exit's IP.
    let real_ip = kind == ExitKind::Dedicated || direct || (f.seen_ip.is_some() && f.seen_ip == f.confirmed_ip);
    reachable && real_ip
}

/// Searches when the node has no peers and announces while it lends, until the node stops.
pub async fn run(handle: NodeHandle, config: RendezvousConfig, lending: Option<ExitKind>, allow_private: bool) {
    let start = Instant::now();
    let mut next_search = start + config.search_after;
    let mut search_retry = config.search_retry;
    let mut next_announce = start + POLL;
    loop {
        tokio::time::sleep(POLL).await;
        let Ok(peers) = handle.routing_peers().await else {
            return; // the node stopped
        };
        let now = Instant::now();
        if !peers.is_empty() {
            search_retry = config.search_retry;
            next_search = now + config.search_after;
        } else if now >= next_search {
            match search(&handle, &config, allow_private).await {
                Ok(0) => info!("no dvpn peers found on the BitTorrent DHT yet; trying again in {} s", search_retry.as_secs()),
                Ok(n) => info!("found {n} possible dvpn peers on the BitTorrent DHT; contacting them"),
                Err(e) => debug!("BitTorrent DHT search failed: {}", addrs::redact(&format!("{e:#}"))),
            }
            next_search = Instant::now() + search_retry;
            search_retry = (search_retry * 2).min(SEARCH_RETRY_MAX);
        }
        if lending.is_some() && now >= next_announce {
            next_announce = Instant::now()
                + match announce(&handle, &config, lending).await {
                    Ok(true) => ANNOUNCE_INTERVAL,
                    Ok(false) => ANNOUNCE_RECHECK,
                    Err(e) => {
                        debug!("BitTorrent DHT announcement failed: {}", addrs::redact(&format!("{e:#}")));
                        ANNOUNCE_RETRY
                    }
                };
        }
    }
}

/// A fresh DHT client, joined to the network.
async fn open(config: &RendezvousConfig) -> anyhow::Result<AsyncDht> {
    let config = config.clone();
    // Building resolves the bootstrap host names and binds a socket: blocking.
    let dht = tokio::task::spawn_blocking(move || {
        let mut builder = Dht::builder();
        if let Some(bootstrap) = &config.mainline_bootstrap {
            builder.bootstrap(bootstrap);
        }
        if let Some(ip) = config.bind {
            builder.bind_address(ip);
        }
        builder.build()
    })
    .await??
    .as_async();
    if !tokio::time::timeout(QUERY_TIMEOUT, dht.bootstrapped()).await.unwrap_or(false) {
        anyhow::bail!("could not join the BitTorrent DHT");
    }
    Ok(dht)
}

/// Looks up the rendezvous keys and dials what they hold. Returns how many peers it dialled.
async fn search(handle: &NodeHandle, config: &RendezvousConfig, allow_private: bool) -> anyhow::Result<usize> {
    let dht = open(config).await?;
    let lookups = search_keys(today()).into_iter().map(|key| {
        let stream = dht.get_peers(key);
        async move {
            let mut found = Vec::new();
            let _ = tokio::time::timeout(QUERY_TIMEOUT, stream.for_each(|peers| {
                found.extend(peers);
                async {}
            }))
            .await;
            found
        }
    });
    let found: Vec<SocketAddrV4> = futures::future::join_all(lookups).await.into_iter().flatten().collect();
    // Our own announcement, if we made one: the IP the DHT sees, or an interface's, with
    // our port. Another node behind the same IP has a different port.
    let seen_ip = dht.info().await.public_address().map(|a| *a.ip());
    drop(dht);
    let listen = handle.listen_addrs().await?;
    let own: Vec<SocketAddrV4> = listen
        .iter()
        .filter_map(|a| Some((ipv4_of(a)?, tcp_port(a)?)))
        .flat_map(|(ip, port)| [Some(SocketAddrV4::new(ip, port)), seen_ip.map(|s| SocketAddrV4::new(s, port))])
        .flatten()
        .collect();
    let dial = candidates(found, &own, allow_private);
    let count = dial.len() / 2;
    if !dial.is_empty() {
        handle.dial_unknown(dial).await?;
    }
    Ok(count)
}

/// Announces our TCP listen port under our shard's key, if [`should_announce`] allows.
async fn announce(handle: &NodeHandle, config: &RendezvousConfig, lending: Option<ExitKind>) -> anyhow::Result<bool> {
    let listen = handle.listen_addrs().await?;
    let Some(port) = listen.iter().filter(|a| !addrs::is_circuit(a)).find_map(tcp_port) else {
        return Ok(false);
    };
    let status: NodeStatus = handle.status().await?;
    let mut facts = Facts {
        lending,
        publicly_reachable: status.publicly_reachable,
        nat: Some(status.nat),
        seen_ip: None,
        interface_ips: listen.iter().filter_map(ipv4_of).collect(),
        confirmed_ip: status.confirmed_public_ip,
    };
    // Settles it without touching the DHT for the usual case: a user behind NAT.
    if !facts.publicly_reachable && !facts.interface_ips.iter().any(|ip| addrs::is_public_v4(*ip)) {
        return Ok(false);
    }
    let dht = open(config).await?;
    facts.seen_ip = dht.info().await.public_address().map(|a| *a.ip());
    if !should_announce(&facts) {
        return Ok(false);
    }
    let shard = records::shard_of(&handle.peer_id()) % SHARDS;
    tokio::time::timeout(QUERY_TIMEOUT, dht.announce_peer(key(shard, today()), Some(port)))
        .await
        .map_err(|_| anyhow::anyhow!("timed out"))??;
    debug!("announced on the BitTorrent DHT");
    Ok(true)
}

fn tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

fn ipv4_of(addr: &Multiaddr) -> Option<Ipv4Addr> {
    match addrs::ip_of(addr)? {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Not documentation ranges: those count as private (crate::addrs).
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(81, 2, 69, 142);
    const EXIT: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    #[test]
    fn keys_differ_per_shard_and_day_and_stay_stable() {
        assert_eq!(key(0, 20_000), key(0, 20_000));
        assert_ne!(key(0, 20_000), key(1, 20_000));
        assert_ne!(key(0, 20_000), key(0, 20_001));
        let keys = search_keys(20_001);
        assert_eq!(keys.len(), 2 * SHARDS as usize);
        assert!(keys.contains(&key(SHARDS - 1, 20_000)), "yesterday's keys too");
    }

    #[test]
    fn candidates_skip_ourselves_private_and_duplicate_ips() {
        let found = [
            SocketAddrV4::new(PUBLIC, 4001),
            SocketAddrV4::new(PUBLIC, 4002),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 4), 4001),
            SocketAddrV4::new(EXIT, 4001),
            SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 35), 0),
        ];
        let dial = candidates(found, &[SocketAddrV4::new(EXIT, 4001)], false);
        assert_eq!(dial.len(), 2, "one public peer, as TCP and QUIC: {dial:?}");
        assert!(dial.iter().all(|a| addrs::ip_of(a) == Some(PUBLIC.into())));
        assert_eq!(candidates(found, &[], true).len(), 6, "private allowed: three IPs");
    }

    #[test]
    fn candidates_are_capped() {
        let found = (1..=100).map(|i| SocketAddrV4::new(Ipv4Addr::new(81, 2, 69, i), 4001));
        assert_eq!(candidates(found, &[], false).len(), 2 * MAX_DIALS);
    }

    fn user(f: Facts) -> Facts {
        Facts {
            lending: Some(ExitKind::User),
            ..f
        }
    }

    #[test]
    fn only_lending_nodes_announce() {
        let facts = Facts {
            publicly_reachable: true,
            seen_ip: Some(PUBLIC),
            interface_ips: vec![PUBLIC],
            ..Facts::default()
        };
        assert!(!should_announce(&facts));
        assert!(should_announce(&user(facts)));
    }

    #[test]
    fn a_node_alone_announces_when_its_interface_has_the_public_ip() {
        let facts = user(Facts {
            nat: Some(NatState::Unknown),
            seen_ip: Some(PUBLIC),
            interface_ips: vec![PUBLIC],
            ..Facts::default()
        });
        assert!(should_announce(&facts));
        let behind_nat = Facts {
            interface_ips: vec![Ipv4Addr::new(192, 168, 1, 4)],
            ..facts.clone()
        };
        assert!(!should_announce(&behind_nat), "not known to be reachable");
        let private = Facts {
            nat: Some(NatState::Private),
            ..facts
        };
        assert!(!should_announce(&private), "AutoNAT says unreachable");
    }

    #[test]
    fn a_connected_user_never_announces_its_exits_ip() {
        // Reachable behind a forwarded port, but the DHT sees the exit's IP.
        let facts = user(Facts {
            publicly_reachable: true,
            nat: Some(NatState::Public),
            seen_ip: Some(EXIT),
            interface_ips: vec![Ipv4Addr::new(192, 168, 1, 4)],
            confirmed_ip: Some(PUBLIC),
            ..Facts::default()
        });
        assert!(!should_announce(&facts));
        let disconnected = Facts {
            seen_ip: Some(PUBLIC),
            ..facts.clone()
        };
        assert!(should_announce(&disconnected), "the DHT sees the confirmed IP");
        let unsure = Facts { seen_ip: None, ..facts };
        assert!(!should_announce(&unsure), "the DHT hasn't told us our IP");
    }

    /// Needs the internet: `cargo test --lib rendezvous -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn joins_the_real_bittorrent_dht_and_looks_up_todays_keys() {
        let dht = open(&RendezvousConfig::default()).await.expect("joined");
        assert!(dht.info().await.public_address().is_some(), "the DHT told us our IP");
        for key in search_keys(today()) {
            let found: Vec<_> = tokio::time::timeout(QUERY_TIMEOUT, dht.get_peers(key).collect::<Vec<_>>())
                .await
                .unwrap_or_default();
            println!("{key}: {} responses", found.len());
        }
    }

    #[test]
    fn a_dedicated_exit_announces_once_reachable() {
        let facts = Facts {
            lending: Some(ExitKind::Dedicated),
            publicly_reachable: true,
            ..Facts::default()
        };
        assert!(should_announce(&facts), "behind 1:1 NAT, declared public");
    }
}
