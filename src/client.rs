//! `dvpn connect`: builds a circuit, brings up the TUN device and routes, forwards
//! packets, and rebuilds the circuit when it fails. Routes stay in place while
//! reconnecting. The caller holds a [`crate::platform::tunnel::KillSwitch`] from before this
//! starts until the user disconnects, so traffic is blocked rather than leaked while
//! connecting, reconnecting, and if this fails.
//!
//! Using the network requires lending to it (docs/DESIGN.md §3.9): no circuit is built
//! until our own exit is usable by others, and the circuit is closed (traffic blocked)
//! if lending stays down for [`LENDING_GRACE`].

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use libp2p::{Multiaddr, PeerId};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::addrs::{self, is_circuit};
use crate::circuit::{CircuitError, KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT, Tunnel};
use crate::control::{CircuitReport, Phase, SharedState, Traffic};
use crate::device::{PacketDevice, TunDevice};
use crate::lend::LendingHandle;
use crate::node::{Circuit, NodeHandle};
use crate::packet;
use crate::records::{ExitKind, ExitRecord, now_secs};
use crate::dns::DnsOverTls;
use crate::platform::tunnel::RouteGuard;
use crate::select::{self, Prepare};

const PEER_WAIT: Duration = Duration::from_secs(30);
const DISCOVERY_WAIT: Duration = Duration::from_secs(60);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_EXEMPT_ADDRS: usize = 4;
const LENDING_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// How often a client on another user's exit looks for a dedicated one.
const DEDICATED_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// How long lending may be down while connected before the circuit is closed. Short
/// outages (an AutoNAT re-check, a relay reservation being renewed) don't interrupt.
pub const LENDING_GRACE: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct ConnectOptions {
    pub tun_name: String,
    /// DNS server to use through the tunnel (via systemd-resolved); `None` leaves DNS alone.
    pub dns: Option<Ipv4Addr>,
    pub dns_over_tls: DnsOverTls,
}

/// Candidates kept for reconnecting while the tunnel (and with it the DHT) is down.
#[derive(Default)]
struct Candidates {
    exits: Vec<ExitRecord>,
    relays: Vec<PeerId>,
}

/// Marks the kill switch as in place for as long as it lives (also when the client
/// future is dropped, e.g. on disconnect).
struct Protected(SharedState);

impl Protected {
    fn set(state: &SharedState) -> Self {
        state.protected.store(true, Ordering::Relaxed);
        Self(state.clone())
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        self.0.protected.store(false, Ordering::Relaxed);
        self.0.warnings.lock().expect("state lock").clear();
    }
}

enum Interruption {
    CircuitLost(anyhow::Error),
    LendingDown,
    /// We were on another user's exit and a dedicated one is now up (make-before-break).
    DedicatedExitUp(Box<Circuit>),
}

/// Runs until the device fails or the future is dropped (which restores routing; the
/// caller's kill switch keeps blocking).
/// `state.lending` must be set: connecting without lending is refused.
pub async fn run(handle: NodeHandle, options: ConnectOptions, state: SharedState) -> anyhow::Result<()> {
    let lending = state.lending.clone().context("connecting requires lending, but no exit is running")?;
    wait_for_peers(&handle).await?;
    state.set_phase(Phase::WaitingForLending);
    wait_for_lending(&handle, &lending).await;

    state.set_phase(Phase::Connecting);
    let candidates = Arc::new(Mutex::new(discover(&handle).await?));
    let mut circuit = first_circuit(&handle, &candidates, &lending, &state).await?;
    let mut assigned_ip = circuit.tunnel.assigned_ip;
    let device = TunDevice::create(&options.tun_name, assigned_ip, 32, circuit.tunnel.mtu)
        .with_context(|| format!("creating TUN device {}", options.tun_name))?;

    // Locked only briefly and never across an await: test circuits exempt relays in parallel.
    let routes = RouteGuard::install(&options.tun_name, options.dns, options.dns_over_tls)?;
    *state.warnings.lock().expect("state lock") = routes.warnings.clone();
    let routes = Mutex::new(routes);
    // Declared after `routes`, so it drops (reporting "unprotected") before they go.
    let _protected = Protected::set(&state);
    let connected = handle.connected_addrs(circuit.relay).await?;
    let relay_ips = direct_ipv4s(&connected);
    if relay_ips.is_empty() {
        bail!("no direct connection to the entry relay; cannot route around the tunnel");
    }
    for ip in relay_ips {
        routes.lock().expect("routes lock").exempt(ip)?;
    }

    // Keep candidates fresh; while connected, these lookups go through the tunnel.
    let refresher = tokio::spawn(refresh(handle.clone(), candidates.clone()));
    let result = loop {
        let info = exit_info(&candidates, circuit.exit);
        let kind = info.kind;
        publish(&state, Some((&circuit, &info)));
        state.set_phase(Phase::Connected);
        state.set_error(None);
        info!(?kind, "tunnel up");
        tracing::debug!(relay = %circuit.relay, exit = %circuit.exit, "circuit");
        let interruption = tokio::select! {
            error = pump_counting(&device, &mut circuit.tunnel, &state.traffic) => Interruption::CircuitLost(error),
            () = lending_lost(&handle, &lending) => Interruption::LendingDown,
            new = dedicated_exit_up(&handle, &routes, &lending, &state), if kind == ExitKind::User => {
                Interruption::DedicatedExitUp(Box::new(new))
            }
        };
        publish(&state, None);
        let next = match interruption {
            Interruption::CircuitLost(error) => {
                warn!("circuit lost ({error:#}); traffic is blocked until a new circuit is up");
                state.set_error(Some(format!("circuit lost: {error:#}")));
                None
            }
            Interruption::LendingDown => {
                drop(circuit);
                warn!("lending has been down for {}s; VPN paused, traffic is blocked until it is back", LENDING_GRACE.as_secs());
                state.set_phase(Phase::Paused);
                state.set_error(Some("lending is down: others can't reach your exit".into()));
                wait_for_lending(&handle, &lending).await;
                None
            }
            Interruption::DedicatedExitUp(new) => {
                info!("a dedicated exit is available; leaving the exit lent by another user");
                Some(*new)
            }
        };

        circuit = match next {
            Some(new) => new,
            None => {
                state.set_phase(Phase::Reconnecting);
                reconnect(&handle, &routes, &candidates, &lending, &state).await
            }
        };
        if circuit.tunnel.assigned_ip != assigned_ip {
            if let Err(e) = device.replace_address(assigned_ip, circuit.tunnel.assigned_ip, 32) {
                break Err(e).context("updating the TUN address");
            }
            assigned_ip = circuit.tunnel.assigned_ip;
        }
        // Whatever happened to the device meanwhile, the kill switch must still be in place.
        if let Err(e) = routes.lock().expect("routes lock").reassert() {
            break Err(e).context("restoring the kill-switch routes");
        }
    };
    refresher.abort();
    lending.pool.reserve(None);
    result
}

/// Waits until our exit is usable by others. No timeout: lending is the price of use.
async fn wait_for_lending(handle: &NodeHandle, lending: &LendingHandle) {
    let mut announced = false;
    loop {
        if lending_ready_now(handle, lending).await {
            info!("lending is ready: others can use your exit");
            return;
        }
        if !announced {
            info!("waiting until your exit is published and reachable before connecting");
            announced = true;
        }
        tokio::time::sleep(LENDING_CHECK_INTERVAL).await;
    }
}

/// Completes once lending has been down for [`LENDING_GRACE`] without a break.
async fn lending_lost(handle: &NodeHandle, lending: &LendingHandle) {
    let mut down_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(LENDING_CHECK_INTERVAL).await;
        if lending_ready_now(handle, lending).await {
            if down_since.take().is_some() {
                info!("lending is back");
            }
            continue;
        }
        match down_since {
            None => {
                warn!("lending is down; the VPN pauses in {}s unless it recovers", LENDING_GRACE.as_secs());
                down_since = Some(Instant::now());
            }
            Some(since) if since.elapsed() >= LENDING_GRACE => return,
            Some(_) => {}
        }
    }
}

async fn lending_ready_now(handle: &NodeHandle, lending: &LendingHandle) -> bool {
    handle.status().await.is_ok_and(|status| lending.ready(&status))
}

/// Takes the circuit's address for our own tunnel, unless our exit already leased it
/// to someone else (both draw from the same range).
fn claim_address(lending: &LendingHandle, circuit: &Circuit) -> anyhow::Result<()> {
    let ip = circuit.tunnel.assigned_ip;
    lending.pool.reserve(Some(ip));
    if lending.pool.is_leased(ip) {
        bail!("the exit assigned {ip}, which our own exit is already using; trying another circuit");
    }
    Ok(())
}

async fn wait_for_peers(handle: &NodeHandle) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + PEER_WAIT;
    while handle.routing_peers().await?.is_empty() {
        if tokio::time::Instant::now() > deadline {
            bail!("could not reach any other peer; add an invite link or a bootstrap peer from someone already in the network");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

async fn discover(handle: &NodeHandle) -> anyhow::Result<Candidates> {
    let deadline = tokio::time::Instant::now() + DISCOVERY_WAIT;
    loop {
        let exits = handle.find_exits().await?;
        let relays = handle.find_relays().await?;
        if !exits.is_empty() && !relays.is_empty() {
            info!(exits = exits.len(), relays = relays.len(), "found circuit candidates");
            return Ok(Candidates { exits, relays });
        }
        if tokio::time::Instant::now() > deadline {
            bail!("found {} exits and {} relays; need at least one of each", exits.len(), relays.len());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn refresh(handle: NodeHandle, candidates: Arc<Mutex<Candidates>>) {
    loop {
        tokio::time::sleep(REFRESH_INTERVAL).await;
        let (Ok(exits), Ok(relays)) = (handle.find_exits().await, handle.find_relays().await) else {
            continue;
        };
        update(&candidates, exits, relays);
    }
}

/// Replaces candidates with fresh lookup results, keeping the old ones if a lookup came back empty.
fn update(candidates: &Mutex<Candidates>, exits: Vec<ExitRecord>, relays: Vec<PeerId>) {
    let mut current = candidates.lock().expect("candidates lock");
    if !exits.is_empty() {
        current.exits = exits;
    }
    if !relays.is_empty() {
        current.relays = relays;
    }
}

/// Retries with backoff until the first circuit is up, looking up candidates again
/// between attempts: records of exits that went offline stay in the DHT until they
/// expire, and exits that joined recently may not have been found yet. No routes are
/// installed yet, so the DHT is reachable directly and nothing can leak.
async fn first_circuit(
    handle: &NodeHandle,
    candidates: &Mutex<Candidates>,
    lending: &LendingHandle,
    state: &SharedState,
) -> anyhow::Result<Circuit> {
    let mut backoff = Duration::from_secs(1);
    loop {
        match try_circuit(handle, candidates, lending, state, &|_, _| Ok(())).await {
            Ok(circuit) => return Ok(circuit),
            Err(e) => {
                warn!("connecting failed ({e:#}); retrying in {}s", backoff.as_secs());
                state.set_error(Some(format!("{e:#}")));
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
        update(candidates, handle.find_exits().await?, handle.find_relays().await?);
    }
}

fn snapshot(candidates: &Mutex<Candidates>) -> (Vec<ExitRecord>, Vec<PeerId>) {
    let c = candidates.lock().expect("candidates lock");
    (c.exits.clone(), c.relays.clone())
}

/// Retries with backoff until a circuit is up. Each candidate relay is routed around
/// the tunnel first, since the tunnel itself is down.
async fn reconnect(
    handle: &NodeHandle,
    routes: &Mutex<RouteGuard>,
    candidates: &Mutex<Candidates>,
    lending: &LendingHandle,
    state: &SharedState,
) -> Circuit {
    let mut backoff = Duration::from_secs(1);
    loop {
        match try_circuit(handle, candidates, lending, state, &|_, addrs| exempt_relay(routes, addrs)).await {
            Ok(circuit) => return circuit,
            Err(e) => {
                warn!("reconnect failed ({e:#}); retrying in {}s", backoff.as_secs());
                state.set_error(Some(format!("{e:#}")));
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                // Exits may have joined or left meanwhile.
                if let (Ok(exits), Ok(relays)) = (handle.find_exits().await, handle.find_relays().await) {
                    update(candidates, exits, relays);
                }
            }
        }
    }
}

/// Routes a candidate relay around the tunnel, which is down or about to be replaced.
fn exempt_relay(routes: &Mutex<RouteGuard>, relay_addrs: &[Multiaddr]) -> anyhow::Result<()> {
    let ips: Vec<Ipv4Addr> = direct_ipv4s(relay_addrs).into_iter().take(MAX_EXEMPT_ADDRS).collect();
    if ips.is_empty() {
        bail!("relay has no direct IPv4 address");
    }
    ips.into_iter().try_for_each(|ip| routes.lock().expect("routes lock").exempt(ip))
}

/// While on another user's exit: completes with a circuit to a dedicated exit as soon as
/// one can be built, under the current selection mode. Dedicated exits that are listed
/// but down just mean we stay where we are.
async fn dedicated_exit_up(
    handle: &NodeHandle,
    routes: &Mutex<RouteGuard>,
    lending: &LendingHandle,
    state: &SharedState,
) -> Circuit {
    loop {
        tokio::time::sleep(DEDICATED_CHECK_INTERVAL).await;
        let (Ok(exits), Ok(relays)) = (handle.find_exits().await, handle.find_relays().await) else {
            continue;
        };
        let (dedicated, _) = select::split_tiers(exits);
        if dedicated.is_empty() {
            continue;
        }
        let selection = *state.selection.lock().expect("state lock");
        let (result, _) = select::open(handle, dedicated, relays, selection, &|_, addrs| exempt_relay(routes, addrs)).await;
        if let Ok(circuit) = result
            && claim_address(lending, &circuit).is_ok()
        {
            return circuit;
        }
    }
}

/// What the client knows about an exit from its record.
struct ExitInfo {
    kind: ExitKind,
    /// Where the exit's traffic appears to come from.
    public_ip: Option<Ipv4Addr>,
}

fn exit_info(candidates: &Mutex<Candidates>, exit: PeerId) -> ExitInfo {
    let candidates = candidates.lock().expect("candidates lock");
    let record = candidates.exits.iter().find(|e| e.peer_id == exit);
    ExitInfo {
        // An exit we have no record for can't be told apart; treat it as dedicated.
        kind: record.map_or(ExitKind::Dedicated, |e| e.kind),
        public_ip: record.and_then(|e| public_ipv4(&e.addrs)),
    }
}

/// The first public IPv4 address that isn't a relay's (in a relay circuit address).
fn public_ipv4(addrs: &[Multiaddr]) -> Option<Ipv4Addr> {
    addrs.iter().filter(|a| !addrs::is_circuit(a)).find_map(|a| match addrs::ip_of(a) {
        Some(std::net::IpAddr::V4(ip)) if addrs::is_public_v4(ip) => Some(ip),
        _ => None,
    })
}

/// One attempt at a circuit under the current selection mode, publishing the probe
/// report for max-ping mode.
async fn try_circuit(
    handle: &NodeHandle,
    candidates: &Mutex<Candidates>,
    lending: &LendingHandle,
    state: &SharedState,
    prepare: Prepare<'_>,
) -> anyhow::Result<Circuit> {
    let (exits, relays) = snapshot(candidates);
    let selection = *state.selection.lock().expect("state lock");
    let (result, report) = select::open(handle, exits, relays, selection, prepare).await;
    if report.is_some() {
        *state.probe.lock().expect("state lock") = report;
    }
    let circuit = result?;
    claim_address(lending, &circuit)?;
    Ok(circuit)
}

fn direct_ipv4s(addrs: &[Multiaddr]) -> Vec<Ipv4Addr> {
    let mut ips: Vec<Ipv4Addr> = addrs
        .iter()
        .filter(|a| !is_circuit(a))
        .filter_map(addrs::ip_of)
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    ips.sort();
    ips.dedup();
    ips
}

fn publish(state: &SharedState, circuit: Option<(&Circuit, &ExitInfo)>) {
    state.traffic.new_circuit();
    *state.datagrams.lock().expect("state lock") = circuit.and_then(|(c, _)| c.tunnel.datagram_liveness());
    *state.circuit.lock().expect("state lock") = circuit.map(|(c, info)| CircuitReport {
        relay: c.relay.to_string(),
        exit: c.exit.to_string(),
        exit_is_user: info.kind == ExitKind::User,
        assigned_ip: c.tunnel.assigned_ip.to_string(),
        connected_since: now_secs(),
        datagrams: false,
        exit_ip: info.public_ip.map(|ip| ip.to_string()),
        rtt_ms: None,
        bytes_sent: 0,
        bytes_received: 0,
    });
}

/// How often the pump checks whether a keepalive is due; randomized so keepalives
/// don't follow a fixed rhythm.
fn keepalive_check_delay() -> Duration {
    Duration::from_millis(rand::random_range(4_000..6_000))
}

/// Moves packets between the TUN device and the tunnel until either side fails or the
/// exit has been silent for [`KEEPALIVE_TIMEOUT`] (it may vanish without closing anything).
pub async fn pump<D: PacketDevice>(device: &D, tunnel: &mut Tunnel) -> anyhow::Error {
    pump_counting(device, tunnel, &Traffic::default()).await
}

/// Like [`pump`], counting the traffic in `traffic` and timing keepalives (the exit
/// answers each) for the circuit's latency.
pub async fn pump_counting<D: PacketDevice>(device: &D, tunnel: &mut Tunnel, traffic: &Traffic) -> anyhow::Error {
    let assigned = tunnel.assigned_ip;
    let Tunnel { tx, rx, .. } = tunnel;
    let last_received = Mutex::new(Instant::now());
    // When the keepalive whose answer we wait for was sent.
    let probe = Mutex::new(None::<Instant>);
    let outbound = async {
        let mut buf = vec![0u8; 65536];
        // One right away, so the latency is known from the start.
        tx.send(&[]).await?;
        *probe.lock().expect("pump lock") = Some(Instant::now());
        let mut last_sent = Instant::now();
        let check = tokio::time::sleep(keepalive_check_delay());
        tokio::pin!(check);
        loop {
            let received = tokio::select! {
                n = device.recv(&mut buf) => Some(n?),
                () = &mut check => None,
            };
            let Some(n) = received else {
                check.as_mut().reset(Instant::now() + keepalive_check_delay());
                let silent = last_received.lock().expect("pump lock").elapsed();
                if silent >= KEEPALIVE_TIMEOUT {
                    return Err(anyhow::anyhow!("exit stopped responding"));
                }
                if silent >= KEEPALIVE_INTERVAL || last_sent.elapsed() >= KEEPALIVE_INTERVAL {
                    tx.send(&[]).await?;
                    last_sent = Instant::now();
                    probe.lock().expect("pump lock").get_or_insert(last_sent);
                }
                continue;
            };
            let packet = &buf[..n];
            // Only our own IPv4 traffic enters the tunnel (the exit would drop the rest).
            if packet::parse(packet).is_none_or(|p| p.src != assigned) {
                continue;
            }
            match tx.send(packet).await {
                Ok(()) => {
                    last_sent = Instant::now();
                    traffic.sent.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(CircuitError::PacketTooLarge) => {}
                Err(e) => return Err::<Infallible, anyhow::Error>(e.into()),
            }
        }
    };
    let inbound = async {
        loop {
            let received = rx.recv().await?;
            // Anything from the exit counts, including its keepalive answers.
            *last_received.lock().expect("pump lock") = Instant::now();
            match received {
                Some(packet) if packet.is_empty() => {
                    if let Some(sent) = probe.lock().expect("pump lock").take() {
                        traffic.add_rtt(sent.elapsed());
                    }
                }
                Some(packet) if packet::parse(&packet).is_some_and(|p| p.dst == assigned) => {
                    device.send(&packet).await?;
                    traffic.received.fetch_add(packet.len() as u64, Ordering::Relaxed);
                }
                Some(_) => {}
                None => return Err::<Infallible, anyhow::Error>(anyhow::anyhow!("exit closed the tunnel")),
            }
        }
    };
    tokio::select! {
        Err(e) = outbound => e,
        Err(e) = inbound => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_ip_shown_is_its_own_public_one() {
        let addrs = |list: &[&str]| list.iter().map(|a| a.parse::<Multiaddr>().unwrap()).collect::<Vec<_>>();
        let relayed = "/ip4/8.8.8.8/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA/p2p-circuit";
        assert_eq!(public_ipv4(&addrs(&[relayed])), None, "a relay's IP isn't where traffic leaves");
        assert_eq!(public_ipv4(&addrs(&["/ip4/192.168.1.4/tcp/4001", relayed])), None, "nor a private one");
        assert_eq!(
            public_ipv4(&addrs(&["/ip4/192.168.1.4/tcp/4001", relayed, "/ip4/8.8.4.4/udp/4001/quic-v1"])),
            Some(Ipv4Addr::new(8, 8, 4, 4))
        );
    }
}
