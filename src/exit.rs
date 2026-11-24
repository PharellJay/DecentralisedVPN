//! Exit forwarding: sessions ⇄ exit TUN, with policy and per-session rate limits.
//!
//! Outbound packets are checked against the [`ExitPolicy`] (including anti-spoofing)
//! before they reach the TUN device. Return traffic is routed to the session that owns
//! the destination virtual address.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::circuit::{EXIT_IDLE_TIMEOUT, ExitSession, Tunnel};
use crate::device::PacketDevice;
use crate::packet;
use crate::policy::ExitPolicy;
use crate::ratelimit::TokenBucket;

pub const EXIT_TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
pub const EXIT_TUN_PREFIX: u8 = 16;
const SESSION_QUEUE: usize = 256;

pub struct ExitOptions {
    pub policy: ExitPolicy,
    /// Per session and direction; 0 = unlimited.
    pub rate_mbps: u64,
}

/// Which session owns each virtual address. Read for every return packet, written only
/// when sessions start and end.
type Routes = Arc<RwLock<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>>;

/// Forwards every session from `sessions` through `device` until `sessions` closes.
pub async fn forward<D: PacketDevice>(
    device: Arc<D>,
    sessions: mpsc::Receiver<ExitSession>,
    options: Arc<ExitOptions>,
    active: Arc<AtomicUsize>,
) {
    forward_queues(vec![device], sessions, options, active).await;
}

/// Like [`forward`], over the queues of a multi-queue device: each queue has its own
/// reader, and sessions are spread over the queues for writing.
pub async fn forward_queues<D: PacketDevice>(
    queues: Vec<Arc<D>>,
    mut sessions: mpsc::Receiver<ExitSession>,
    options: Arc<ExitOptions>,
    active: Arc<AtomicUsize>,
) {
    assert!(!queues.is_empty(), "a device has at least one queue");
    let routes: Routes = Arc::default();
    let readers: Vec<_> = queues.iter().map(|queue| tokio::spawn(read_device(queue.clone(), routes.clone()))).collect();
    let mut next = 0;
    while let Some(session) = sessions.recv().await {
        let queue = queues[next % queues.len()].clone();
        next += 1;
        tokio::spawn(serve_session(session.tunnel, queue, routes.clone(), options.clone(), active.clone()));
    }
    for reader in readers {
        reader.abort();
    }
}

/// Delivers return traffic from the TUN device to the owning session.
async fn read_device<D: PacketDevice>(device: Arc<D>, routes: Routes) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match device.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!("exit TUN read failed: {e}");
                return;
            }
        };
        let Some(info) = packet::parse(&buf[..n]) else { continue };
        let routes = routes.read().expect("routes lock");
        if let Some(session) = routes.get(&info.dst) {
            // A full queue means the client is slower than its traffic; drop like a router would.
            let _ = session.try_send(buf[..n].to_vec());
        }
    }
}

async fn serve_session<D: PacketDevice>(
    tunnel: Tunnel,
    device: Arc<D>,
    routes: Routes,
    options: Arc<ExitOptions>,
    active: Arc<AtomicUsize>,
) {
    let Tunnel {
        assigned_ip, mut tx, mut rx, ..
    } = tunnel;
    let (return_tx, mut return_rx) = mpsc::channel::<Vec<u8>>(SESSION_QUEUE);
    routes.write().expect("routes lock").insert(assigned_ip, return_tx.clone());
    active.fetch_add(1, Ordering::Relaxed);

    let outbound = async {
        let mut bucket = TokenBucket::from_mbps(options.rate_mbps);
        // A live client sends something, at least a keepalive, every KEEPALIVE_INTERVAL.
        while let Ok(Ok(Some(packet))) = timeout(EXIT_IDLE_TIMEOUT, rx.recv()).await {
            if packet.is_empty() {
                // Keepalive: answer through the return queue, under the same rate limit.
                let _ = return_tx.try_send(Vec::new());
                continue;
            }
            match options.policy.check(&packet, assigned_ip) {
                Ok(()) => {
                    bucket.take(packet.len()).await;
                    if device.send(&packet).await.is_err() {
                        break;
                    }
                }
                Err(reason) => debug!(?reason, "exit policy dropped a packet"),
            }
        }
    };
    let inbound = async {
        let mut bucket = TokenBucket::from_mbps(options.rate_mbps);
        while let Some(packet) = return_rx.recv().await {
            bucket.take(packet.len()).await;
            if tx.send(&packet).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = outbound => {}
        _ = inbound => {}
    }

    // Only remove our own entry: the address may already belong to a new session.
    let mut routes = routes.write().expect("routes lock");
    if routes.get(&assigned_ip).is_some_and(|s| s.same_channel(&return_tx)) {
        routes.remove(&assigned_ip);
    }
    active.fetch_sub(1, Ordering::Relaxed);
}
