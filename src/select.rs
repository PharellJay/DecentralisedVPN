//! Choosing an exit (docs/DESIGN.md §3.10).
//!
//! - Dedicated exits (`dvpn run --exit`) come first. Exits lent by other users
//!   (`dvpn connect`) are used only when no dedicated exit fits.
//! - [`Selection::Random`]: any exit, uniformly at random.
//! - [`Selection::MaxPing`]: test circuits are opened to several candidates and a
//!   keepalive is timed through each, so the measured latency is that of the real path
//!   (client → entry relay → exit). Exits never see the client's IP. One exit within the
//!   limit is then picked uniformly at random, so the choice follows no detectable
//!   pattern (not simply "the fastest"), and that test circuit becomes the connection.

use std::fmt;
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use rand::seq::{IndexedRandom, SliceRandom};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, timeout};
use tracing::{debug, info};

use crate::circuit::Tunnel;
use crate::node::{Circuit, NodeHandle};
use crate::records::{ExitKind, ExitRecord};

/// Test circuits opened per tier.
const MAX_PROBES: usize = 8;
/// Keepalive round trips per test circuit; the fastest counts.
const PROBE_SAMPLES: usize = 3;
/// Building a test circuit, including the handshake.
const PROBE_BUILD_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_RETRY_DELAY: Duration = Duration::from_millis(200);
/// Waiting for one keepalive answer (or the limit, if higher).
const PROBE_ANSWER_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selection {
    /// Any exit, uniformly at random. Most private; may be slow.
    #[default]
    Random,
    /// A random exit among those whose measured latency is at most this.
    MaxPing(Duration),
}

impl fmt::Display for Selection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => write!(f, "random"),
            Self::MaxPing(limit) => write!(f, "max ping {} ms", limit.as_millis()),
        }
    }
}

/// What the last max-ping search found, so it can be shown to the user.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    pub limit_ms: u64,
    /// Exits a test circuit could be built to.
    pub measured: usize,
    pub within_limit: usize,
    pub fastest_ms: Option<u64>,
    /// The search had to fall back to exits lent by other users.
    pub used_user_exits: bool,
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = if self.used_user_exits { "exits (incl. other users')" } else { "dedicated exits" };
        write!(f, "{} of {} {source} within {} ms", self.within_limit, self.measured, self.limit_ms)?;
        if let Some(fastest) = self.fastest_ms {
            write!(f, " (fastest {fastest} ms)")?;
        }
        Ok(())
    }
}

/// Called with each candidate relay before it's used (e.g. to route it around the tunnel).
pub type Prepare<'a> = &'a (dyn Fn(PeerId, &[Multiaddr]) -> anyhow::Result<()> + Send + Sync);

/// Opens a circuit according to `selection`. In max-ping mode the report is returned
/// whether or not an exit was found.
pub async fn open(
    handle: &NodeHandle,
    exits: Vec<ExitRecord>,
    relays: Vec<PeerId>,
    selection: Selection,
    prepare: Prepare<'_>,
) -> (anyhow::Result<Circuit>, Option<ProbeReport>) {
    let (dedicated, user) = split_tiers(exits);
    match selection {
        Selection::Random => (open_random(handle, dedicated, user, relays, prepare).await, None),
        Selection::MaxPing(limit) => {
            let (result, report) = open_within(handle, dedicated, user, relays, limit, prepare).await;
            (result, Some(report))
        }
    }
}

/// Dedicated exits first, then exits lent by users (connect + lend), each shuffled later.
pub fn split_tiers(exits: Vec<ExitRecord>) -> (Vec<ExitRecord>, Vec<ExitRecord>) {
    exits.into_iter().partition(|e| e.kind == ExitKind::Dedicated)
}

async fn open_random(
    handle: &NodeHandle,
    dedicated: Vec<ExitRecord>,
    user: Vec<ExitRecord>,
    relays: Vec<PeerId>,
    prepare: Prepare<'_>,
) -> anyhow::Result<Circuit> {
    let mut last_error = anyhow::anyhow!("no exits found in the network");
    for (tier, exits) in [(ExitKind::Dedicated, dedicated), (ExitKind::User, user)] {
        if exits.is_empty() {
            continue;
        }
        if tier == ExitKind::User {
            info!("no dedicated exit is available; using an exit lent by another user");
        }
        match handle.open_circuit_from(exits, relays.clone(), |p, a| prepare(p, a)).await {
            Ok(circuit) => return Ok(circuit),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

async fn open_within(
    handle: &NodeHandle,
    dedicated: Vec<ExitRecord>,
    user: Vec<ExitRecord>,
    relays: Vec<PeerId>,
    limit: Duration,
    prepare: Prepare<'_>,
) -> (anyhow::Result<Circuit>, ProbeReport) {
    let mut report = ProbeReport {
        limit_ms: limit.as_millis() as u64,
        ..ProbeReport::default()
    };
    for (tier, mut exits) in [(ExitKind::Dedicated, dedicated), (ExitKind::User, user)] {
        if exits.is_empty() {
            continue;
        }
        report.used_user_exits = tier == ExitKind::User;
        exits.shuffle(&mut rand::rng());
        exits.truncate(MAX_PROBES);
        let probes = exits.into_iter().map(|exit| probe(handle, exit, relays.clone(), limit, prepare));
        let mut measured: Vec<(Circuit, Duration)> = futures::future::join_all(probes).await.into_iter().flatten().collect();

        report.measured += measured.len();
        report.within_limit = measured.iter().filter(|(_, rtt)| *rtt <= limit).count();
        let fastest = measured.iter().map(|(_, rtt)| rtt.as_millis() as u64).min();
        report.fastest_ms = report.fastest_ms.into_iter().chain(fastest).min();
        if let Some(i) = pick_within(&measured, limit) {
            // The other test circuits close as they drop.
            let (circuit, rtt) = measured.swap_remove(i);
            info!("{report}; picked one at random ({} ms)", rtt.as_millis());
            return (Ok(circuit), report);
        }
    }
    (Err(anyhow::anyhow!("no exit within {} ms: {report}", limit.as_millis())), report)
}

/// Builds a test circuit to `exit` and measures its round-trip time.
async fn probe(
    handle: &NodeHandle,
    exit: ExitRecord,
    relays: Vec<PeerId>,
    limit: Duration,
    prepare: Prepare<'_>,
) -> Option<(Circuit, Duration)> {
    let peer = exit.peer_id;
    let mut circuit = None;
    // Parallel test circuits can race on a fresh connection to the relay ("connection is
    // closed"), so a quick failure gets one retry; a timeout doesn't.
    for attempt in 0..2 {
        let build = handle.open_circuit_from(vec![exit.clone()], relays.clone(), |p, a| prepare(p, a));
        match timeout(PROBE_BUILD_TIMEOUT, build).await {
            Ok(Ok(built)) => {
                circuit = Some(built);
                break;
            }
            Ok(Err(e)) => debug!(exit = %peer, attempt, "test circuit failed: {e:#}"),
            Err(_) => {
                debug!(exit = %peer, "test circuit timed out");
                return None;
            }
        }
        tokio::time::sleep(PROBE_RETRY_DELAY).await;
    }
    let mut circuit = circuit?;
    let rtt = measure_rtt(&mut circuit.tunnel, PROBE_ANSWER_TIMEOUT.max(limit)).await;
    if rtt.is_none() {
        debug!(exit = %peer, "exit did not answer the test circuit's keepalives");
    }
    Some((circuit, rtt?))
}

/// The fastest of a few keepalive round trips through `tunnel` (the exit answers each
/// keepalive). `None` if the exit doesn't answer within `wait`; the tunnel should
/// then be discarded.
pub async fn measure_rtt(tunnel: &mut Tunnel, wait: Duration) -> Option<Duration> {
    let mut best: Option<Duration> = None;
    for _ in 0..PROBE_SAMPLES {
        let started = Instant::now();
        tunnel.tx.send(&[]).await.ok()?;
        let answered = timeout(wait, async {
            loop {
                match tunnel.rx.recv().await {
                    Ok(Some(packet)) if packet.is_empty() => return true,
                    Ok(Some(_)) => continue,
                    _ => return false,
                }
            }
        })
        .await;
        if answered != Ok(true) {
            return None;
        }
        let rtt = started.elapsed();
        best = Some(best.map_or(rtt, |b| b.min(rtt)));
    }
    best
}

/// One exit's latency, measured through a test circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub exit: PeerId,
    pub kind: ExitKind,
    pub rtt: Duration,
}

/// Measures up to [`MAX_PROBES`] exits of each kind through test circuits, which are
/// closed afterwards. Used to show how many exits fit a limit before connecting.
pub async fn measure_exits(
    handle: &NodeHandle,
    exits: Vec<ExitRecord>,
    relays: Vec<PeerId>,
    prepare: Prepare<'_>,
) -> Vec<Measurement> {
    let (dedicated, user) = split_tiers(exits);
    let mut sample = Vec::new();
    for mut tier in [dedicated, user] {
        tier.shuffle(&mut rand::rng());
        tier.truncate(MAX_PROBES);
        sample.extend(tier);
    }
    let probes = sample.into_iter().map(|exit| {
        let relays = relays.clone();
        async move {
            let (peer, kind) = (exit.peer_id, exit.kind);
            let (_circuit, rtt) = probe(handle, exit, relays, Duration::ZERO, prepare).await?;
            Some(Measurement { exit: peer, kind, rtt })
        }
    });
    futures::future::join_all(probes).await.into_iter().flatten().collect()
}

/// How many measured exits fit `limit`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Availability {
    pub dedicated: usize,
    /// Exits lent by other users; used only if `dedicated` is 0.
    pub user: usize,
    pub measured: usize,
    pub fastest_ms: Option<u64>,
}

pub fn availability(measurements: &[Measurement], limit: Duration) -> Availability {
    let within = |kind| measurements.iter().filter(|m| m.kind == kind && m.rtt <= limit).count();
    Availability {
        dedicated: within(ExitKind::Dedicated),
        user: within(ExitKind::User),
        measured: measurements.len(),
        fastest_ms: measurements.iter().map(|m| m.rtt.as_millis() as u64).min(),
    }
}

/// A uniformly random entry whose latency is within `limit`.
pub fn pick_within<T>(measured: &[(T, Duration)], limit: Duration) -> Option<usize> {
    let within: Vec<usize> = (0..measured.len()).filter(|&i| measured[i].1 <= limit).collect();
    within.choose(&mut rand::rng()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: ExitKind) -> ExitRecord {
        ExitRecord {
            peer_id: PeerId::random(),
            noise_static: [0; 32],
            addrs: vec![],
            blocked_tcp_ports: vec![],
            kind,
            expires_at: 0,
        }
    }

    #[test]
    fn dedicated_exits_form_the_first_tier() {
        let exits = vec![record(ExitKind::User), record(ExitKind::Dedicated), record(ExitKind::User)];
        let (dedicated, user) = split_tiers(exits);
        assert_eq!(dedicated.len(), 1);
        assert!(dedicated.iter().all(|e| e.kind == ExitKind::Dedicated));
        assert_eq!(user.len(), 2);
    }

    #[test]
    fn picks_only_within_the_limit_and_without_a_pattern() {
        let ms = Duration::from_millis;
        let measured = [("a", ms(20)), ("slow", ms(300)), ("b", ms(80)), ("c", ms(5)), ("slower", ms(81))];
        let mut counts = [0usize; 5];
        for _ in 0..3000 {
            counts[pick_within(&measured, ms(80)).unwrap()] += 1;
        }
        assert_eq!(counts[1] + counts[4], 0, "picked an exit above the limit");
        // Every exit within the limit (80 ms is inclusive) gets picked, roughly equally,
        // not just the fastest.
        for i in [0, 2, 3] {
            assert!(counts[i] > 800, "exit {i} picked {} of 3000 times", counts[i]);
        }
        assert_eq!(pick_within(&measured, ms(4)), None);
        assert_eq!(pick_within::<()>(&[], ms(1000)), None);
    }

    #[test]
    fn availability_counts_each_kind_within_the_limit() {
        let m = |kind, ms| Measurement {
            exit: PeerId::random(),
            kind,
            rtt: Duration::from_millis(ms),
        };
        let measured = [
            m(ExitKind::Dedicated, 40),
            m(ExitKind::Dedicated, 120),
            m(ExitKind::User, 30),
            m(ExitKind::User, 300),
        ];
        let at = |ms| availability(&measured, Duration::from_millis(ms));
        assert_eq!(
            at(50),
            Availability {
                dedicated: 1,
                user: 1,
                measured: 4,
                fastest_ms: Some(30)
            }
        );
        assert_eq!((at(10).dedicated, at(10).user), (0, 0));
        assert_eq!((at(1000).dedicated, at(1000).user), (2, 2));
        assert_eq!(availability(&[], Duration::from_millis(50)), Availability::default());
    }

    #[test]
    fn report_reads_well() {
        let report = ProbeReport {
            limit_ms: 80,
            measured: 5,
            within_limit: 3,
            fastest_ms: Some(23),
            used_user_exits: false,
        };
        assert_eq!(report.to_string(), "3 of 5 dedicated exits within 80 ms (fastest 23 ms)");
        assert_eq!(Selection::MaxPing(Duration::from_millis(80)).to_string(), "max ping 80 ms");
    }
}
