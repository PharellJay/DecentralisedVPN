//! The full packet path without root: client "TUN" → pump → circuit → exit forwarder
//! → exit "TUN", with in-memory devices in place of real TUN interfaces.

mod common;

use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use common::{Opts, start, wait_for};
use dvpn::control::{self, SharedState};
use dvpn::device::PacketDevice;
use dvpn::exit::{self, ExitOptions};
use dvpn::policy::ExitPolicy;
use tokio::sync::{Mutex, mpsc};

/// One side of an in-memory packet device.
struct FakeDevice {
    from_kernel: Mutex<mpsc::Receiver<Vec<u8>>>,
    to_kernel: mpsc::Sender<Vec<u8>>,
}

/// The "kernel" side: inject packets the device will read, collect packets it writes.
struct Kernel {
    inject: mpsc::Sender<Vec<u8>>,
    written: mpsc::Receiver<Vec<u8>>,
}

fn fake_device() -> (Arc<FakeDevice>, Kernel) {
    let (inject, from_kernel) = mpsc::channel(64);
    let (to_kernel, written) = mpsc::channel(64);
    let device = FakeDevice {
        from_kernel: Mutex::new(from_kernel),
        to_kernel,
    };
    (Arc::new(device), Kernel { inject, written })
}

impl PacketDevice for FakeDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self.from_kernel.lock().await.recv().await.ok_or(io::ErrorKind::BrokenPipe)?;
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.to_kernel.send(packet.to_vec()).await.map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(packet.len())
    }
}

/// Minimal IPv4 + TCP/UDP-port packet with a payload.
fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total = 24 + payload.len();
    let mut p = vec![0u8; 24];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = protocol;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

async fn next(kernel: &mut Kernel) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_millis(500), kernel.written.recv()).await.ok().flatten()
}

#[tokio::test]
async fn packets_flow_end_to_end_and_exit_policy_is_enforced() {
    let boot = start(Opts::default()).await;
    let via_boot = || vec![boot.addr.clone().unwrap()];
    let _relay = start(Opts {
        bootstrap: via_boot(),
        relay: true,
        ..Default::default()
    })
    .await;
    let mut exit_node = start(Opts {
        bootstrap: via_boot(),
        exit: true,
        ..Default::default()
    })
    .await;
    let client = start(Opts {
        bootstrap: via_boot(),
        ..Default::default()
    })
    .await;

    // Exit side: forwarder between sessions and an in-memory "dvpn-exit" device.
    let (exit_device, mut exit_kernel) = fake_device();
    let active = Arc::new(AtomicUsize::new(0));
    let options = Arc::new(ExitOptions {
        policy: ExitPolicy::new(["198.51.100.0/24".parse().unwrap()], vec![25]),
        rate_mbps: 0,
    });
    tokio::spawn(exit::forward(exit_device, exit_node.exit_sessions.take().unwrap(), options, active.clone()));

    // Client side: pump between an in-memory "dvpn0" device and the circuit.
    let mut circuit = wait_for("a circuit", || async { client.handle.open_circuit().await.ok() }).await;
    let me = circuit.tunnel.assigned_ip;
    let (client_device, mut client_kernel) = fake_device();
    tokio::spawn(async move { dvpn::client::pump(client_device.as_ref(), &mut circuit.tunnel).await });

    let web = Ipv4Addr::new(93, 184, 216, 34);
    let allowed = ipv4(me, web, 6, 443, b"hello web");
    client_kernel.inject.send(allowed.clone()).await.unwrap();
    assert_eq!(next(&mut exit_kernel).await.as_deref(), Some(allowed.as_slice()), "allowed packet must exit");

    // Each of these must be dropped at the exit (or before).
    let other_client = Ipv4Addr::new(10, 77, 0, 99);
    let dropped = [
        ("spoofed source", ipv4(other_client, web, 6, 443, b"spoof")),
        ("exit's LAN", ipv4(me, Ipv4Addr::new(192, 168, 1, 1), 6, 80, b"lan")),
        ("exit host's own network", ipv4(me, Ipv4Addr::new(198, 51, 100, 20), 6, 22, b"ssh")),
        ("SMTP", ipv4(me, web, 6, 25, b"spam")),
        ("another client", ipv4(me, other_client, 17, 53, b"peer")),
    ];
    for (what, packet) in dropped {
        client_kernel.inject.send(packet).await.unwrap();
        assert_eq!(next(&mut exit_kernel).await, None, "{what} reached the internet");
    }

    // Return traffic for our address reaches the client; traffic for others does not.
    let reply = ipv4(web, me, 6, 40000, b"hello client");
    exit_kernel.inject.send(ipv4(web, other_client, 6, 40000, b"not yours")).await.unwrap();
    exit_kernel.inject.send(reply.clone()).await.unwrap();
    assert_eq!(next(&mut client_kernel).await.as_deref(), Some(reply.as_slice()));
    assert_eq!(next(&mut client_kernel).await, None);
    assert_eq!(active.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn status_socket_reports_and_refuses_a_second_instance() {
    let node = start(Opts::default()).await;
    let listener = control::bind(&node.data_dir).await.unwrap();
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(control::socket_path(&node.data_dir).unwrap()).unwrap().permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
    tokio::spawn(control::serve(listener, node.handle.clone(), SharedState::default()));

    let report = control::query(&node.data_dir).await.unwrap();
    assert_eq!(report.peer_id, node.handle.peer_id().to_string());
    assert!(report.circuit.is_none());

    let second = control::bind(&node.data_dir).await;
    assert!(second.is_err(), "a second instance must not take over the socket");
}
