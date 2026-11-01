//! Helpers for multi-node tests on localhost.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dvpn::circuit::ExitSession;
use dvpn::device::PacketDevice;
use dvpn::exit::{self, ExitOptions};
use dvpn::policy::ExitPolicy;
use dvpn::identity::Identity;
use dvpn::node::{self, ExitConfig, NodeConfig, NodeHandle, Reachability};
use dvpn::records::ExitKind;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tempfile::TempDir;
use tokio::sync::mpsc;

pub const TIMEOUT: Duration = Duration::from_secs(45);

pub struct Opts {
    pub bootstrap: Vec<Multiaddr>,
    pub reachability: Reachability,
    pub relay: bool,
    pub exit: bool,
    pub exit_kind: ExitKind,
    /// Listen on 127.0.0.1; `false` simulates a node behind NAT (outbound only).
    pub listen: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            bootstrap: vec![],
            reachability: Reachability::Public,
            relay: false,
            exit: false,
            exit_kind: ExitKind::Dedicated,
            listen: true,
        }
    }
}

pub struct TestNode {
    pub handle: NodeHandle,
    pub exit_sessions: Option<mpsc::Receiver<ExitSession>>,
    /// Dialable address with `/p2p/<id>`; `None` for nodes without a listener.
    pub addr: Option<Multiaddr>,
    pub data_dir: PathBuf,
    _tmp: Option<TempDir>,
}

pub async fn start(opts: Opts) -> TestNode {
    let tmp = tempfile::tempdir().unwrap();
    let mut node = start_in(tmp.path(), opts).await;
    node._tmp = Some(tmp);
    node
}

/// Starts a node whose data lives in `<tmp>/dvpn` (a fresh 0700 directory).
pub async fn start_in(tmp: &Path, opts: Opts) -> TestNode {
    let dir = tmp.join("dvpn");
    let identity = Identity::load(&dir).or_else(|_| Identity::init(&dir)).unwrap();
    let node = node::spawn(
        identity,
        NodeConfig {
            data_dir: dir.clone(),
            listen: if opts.listen {
                vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
            } else {
                vec![]
            },
            bootstrap: opts.bootstrap,
            mdns: false,
            peer_cache: true,
            reachability: opts.reachability,
            relay: opts.relay,
            relay_rate_mbps: 0,
            exit: opts.exit.then(|| ExitConfig {
                kind: opts.exit_kind,
                max_sessions: 16,
                blocked_tcp_ports: vec![25],
            }),
            allow_private_addrs: true,
        },
    )
    .unwrap();

    let addr = if opts.listen {
        let handle = node.handle.clone();
        let addr = wait_for("listen address", || {
            let handle = handle.clone();
            async move { handle.listen_addrs().await.unwrap().into_iter().next() }
        })
        .await;
        Some(addr.with(Protocol::P2p(node.handle.peer_id())))
    } else {
        None
    };

    TestNode {
        handle: node.handle,
        exit_sessions: node.exit_sessions,
        addr,
        data_dir: dir,
        _tmp: None,
    }
}

/// A packet device with no traffic.
pub struct IdleDevice;

impl PacketDevice for IdleDevice {
    async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        std::future::pending().await
    }
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        Ok(packet.len())
    }
}

/// Runs the real exit forwarder for `node`'s sessions on an idle device, so its
/// sessions behave like a real exit's (e.g. keepalives are answered).
pub fn run_exit_forwarder(node: &mut TestNode) {
    let options = Arc::new(ExitOptions {
        policy: ExitPolicy::new(std::iter::empty(), vec![25]),
        rate_mbps: 0,
    });
    let sessions = node.exit_sessions.take().expect("not an exit");
    tokio::spawn(exit::forward(Arc::new(IdleDevice), sessions, options, Arc::default()));
}

/// Polls `check` until it returns `Some`, panicking after [`TIMEOUT`].
pub async fn wait_for<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let result = tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Some(value) = check().await {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    result.unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}
