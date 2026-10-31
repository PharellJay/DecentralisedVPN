//! `dvpn connect`: builds a circuit, brings up the TUN device and routes, forwards
//! packets, and rebuilds the circuit when it fails. Routes stay in place while
//! reconnecting, so traffic is blocked rather than leaked (kill switch).

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use libp2p::{Multiaddr, PeerId};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::addrs::{self, is_circuit};
use crate::circuit::{CircuitError, KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT, Tunnel};
use crate::control::{CircuitReport, SharedState};
use crate::device::{PacketDevice, TunDevice};
use crate::node::{Circuit, NodeHandle};
use crate::packet;
use crate::records::{ExitRecord, now_secs};
use crate::routes::RouteGuard;

const PEER_WAIT: Duration = Duration::from_secs(30);
const DISCOVERY_WAIT: Duration = Duration::from_secs(60);
const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_EXEMPT_ADDRS: usize = 4;

pub struct ConnectOptions {
    pub tun_name: String,
    /// DNS server to use through the tunnel (via systemd-resolved); `None` leaves DNS alone.
    pub dns: Option<Ipv4Addr>,
}

/// Candidates kept for reconnecting while the tunnel (and with it the DHT) is down.
#[derive(Default)]
struct Candidates {
    exits: Vec<ExitRecord>,
    relays: Vec<PeerId>,
}

/// Runs until the device fails or the future is dropped (which restores routing).
pub async fn run(handle: NodeHandle, options: ConnectOptions, state: SharedState) -> anyhow::Result<()> {
    wait_for_peers(&handle).await?;
    let candidates = Arc::new(Mutex::new(discover(&handle).await?));

    let mut circuit = first_circuit(&handle, &candidates).await?;
    let mut assigned_ip = circuit.tunnel.assigned_ip;
    let device = TunDevice::create(&options.tun_name, assigned_ip, 32, circuit.tunnel.mtu)
        .with_context(|| format!("creating TUN device {}", options.tun_name))?;

    let mut routes = RouteGuard::install(&options.tun_name, options.dns)?;
    let connected = handle.connected_addrs(circuit.relay).await?;
    let relay_ips = direct_ipv4s(&connected);
    if relay_ips.is_empty() {
        bail!("no direct connection to the entry relay; cannot route around the tunnel");
    }
    for ip in relay_ips {
        routes.exempt(ip)?;
    }

    // Keep candidates fresh; while connected, these lookups go through the tunnel.
    let refresher = tokio::spawn(refresh(handle.clone(), candidates.clone()));
    let result = loop {
        publish(&state, Some(&circuit));
        info!(relay = %circuit.relay, exit = %circuit.exit, "tunnel up");
        let error = pump(&device, &mut circuit.tunnel).await;
        publish(&state, None);
        warn!("circuit lost ({error:#}); traffic is blocked until a new circuit is up");

        circuit = reconnect(&handle, &mut routes, &candidates).await;
        if circuit.tunnel.assigned_ip != assigned_ip {
            assigned_ip = circuit.tunnel.assigned_ip;
            if let Err(e) = device.set_address(assigned_ip, 32) {
                break Err(e).context("updating the TUN address");
            }
        }
    };
    refresher.abort();
    result
}

async fn wait_for_peers(handle: &NodeHandle) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + PEER_WAIT;
    while handle.routing_peers().await?.is_empty() {
        if tokio::time::Instant::now() > deadline {
            bail!("could not reach any peers; pass --bootstrap <multiaddr>");
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
async fn first_circuit(handle: &NodeHandle, candidates: &Mutex<Candidates>) -> anyhow::Result<Circuit> {
    let mut backoff = Duration::from_secs(1);
    loop {
        let (exits, relays) = snapshot(candidates);
        match handle.open_circuit_from(exits, relays, |_, _| Ok(())).await {
            Ok(circuit) => return Ok(circuit),
            Err(e) => warn!("connecting failed ({e:#}); retrying in {}s", backoff.as_secs()),
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
async fn reconnect(handle: &NodeHandle, routes: &mut RouteGuard, candidates: &Mutex<Candidates>) -> Circuit {
    let mut backoff = Duration::from_secs(1);
    loop {
        let (exits, relays) = snapshot(candidates);
        let attempt = handle
            .open_circuit_from(exits, relays, |_, relay_addrs| {
                let ips: Vec<Ipv4Addr> = direct_ipv4s(relay_addrs).into_iter().take(MAX_EXEMPT_ADDRS).collect();
                if ips.is_empty() {
                    bail!("relay has no direct IPv4 address");
                }
                ips.into_iter().try_for_each(|ip| routes.exempt(ip))
            })
            .await;
        match attempt {
            Ok(circuit) => return circuit,
            Err(e) => {
                warn!("reconnect failed ({e:#}); retrying in {}s", backoff.as_secs());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
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

fn publish(state: &SharedState, circuit: Option<&Circuit>) {
    *state.circuit.lock().expect("state lock") = circuit.map(|c| CircuitReport {
        relay: c.relay.to_string(),
        exit: c.exit.to_string(),
        assigned_ip: c.tunnel.assigned_ip.to_string(),
        connected_since: now_secs(),
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
    let assigned = tunnel.assigned_ip;
    let Tunnel { tx, rx, .. } = tunnel;
    let last_received = Mutex::new(Instant::now());
    let outbound = async {
        let mut buf = vec![0u8; 65536];
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
                }
                continue;
            };
            let packet = &buf[..n];
            // Only our own IPv4 traffic enters the tunnel (the exit would drop the rest).
            if !packet::parse(packet).is_some_and(|p| p.src == assigned) {
                continue;
            }
            match tx.send(packet).await {
                Ok(()) => last_sent = Instant::now(),
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
                Some(packet) if packet::parse(&packet).is_some_and(|p| p.dst == assigned) => {
                    device.send(&packet).await?;
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
