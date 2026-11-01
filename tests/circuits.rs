//! End-to-end 2-hop circuits between real nodes on localhost.

mod common;

use common::{Opts, TestNode, start, wait_for};
use dvpn::circuit::CircuitError;
use dvpn::identity::Identity;
use dvpn::records::{ExitKind, ExitRecord, now_secs};

/// Bootstrap node + one relay + one exit + a client, all bootstrapped off `boot`.
async fn network() -> (TestNode, TestNode, TestNode, TestNode) {
    let boot = start(Opts::default()).await;
    let via_boot = || vec![boot.addr.clone().unwrap()];
    let relay = start(Opts {
        bootstrap: via_boot(),
        relay: true,
        ..Default::default()
    })
    .await;
    let exit = start(Opts {
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
    let expected = [relay.handle.peer_id(), exit.handle.peer_id()];
    wait_for("client to learn the relay and exit", || async {
        let known = client.handle.routing_peers().await.ok()?;
        expected.iter().all(|p| known.contains(p)).then_some(())
    })
    .await;
    (boot, relay, exit, client)
}

async fn exit_record_of(client: &TestNode, exit: &TestNode) -> ExitRecord {
    wait_for("exit record in the DHT", || async {
        let exits = client.handle.find_exits().await.ok()?;
        exits.into_iter().find(|r| r.peer_id == exit.handle.peer_id())
    })
    .await
}

#[tokio::test]
async fn two_hop_circuit_carries_data_end_to_end() {
    let (_boot, relay, mut exit, client) = network().await;

    // Exit and relay are discovered purely through the DHT.
    let mut circuit = wait_for("a circuit", || async { client.handle.open_circuit().await.ok() }).await;
    assert_eq!(circuit.relay, relay.handle.peer_id());
    assert_eq!(circuit.exit, exit.handle.peer_id());

    let mut session = exit.exit_sessions.as_mut().unwrap().recv().await.unwrap();
    // The exit sees the session arriving from the relay, never from the client.
    assert_eq!(session.via_peer, relay.handle.peer_id());
    assert_ne!(session.via_peer, client.handle.peer_id());
    assert_eq!(session.tunnel.assigned_ip, circuit.tunnel.assigned_ip);

    let request = b"GET / HTTP/1.1 (pretend IP packet)".to_vec();
    circuit.tunnel.tx.send(&request).await.unwrap();
    assert_eq!(session.tunnel.rx.recv().await.unwrap().unwrap(), request);

    let response = b"HTTP/1.1 200 OK (pretend reply)".to_vec();
    session.tunnel.tx.send(&response).await.unwrap();
    assert_eq!(circuit.tunnel.rx.recv().await.unwrap().unwrap(), response);

    // The working entry relay is remembered as the guard.
    assert_eq!(dvpn::guard::load(&client.data_dir), Some(relay.handle.peer_id()));
}

#[tokio::test]
async fn node_without_exit_refuses_exit_traffic() {
    let (boot, relay, _exit, client) = network().await;
    let not_exit = start(Opts {
        bootstrap: vec![boot.addr.clone().unwrap()],
        ..Default::default()
    })
    .await;
    assert!(not_exit.exit_sessions.is_none());

    // Forge the best possible target: the node's real Noise key and address.
    let identity = Identity::load(&not_exit.data_dir).unwrap();
    let target = ExitRecord {
        peer_id: not_exit.handle.peer_id(),
        noise_static: identity.exit_static.public,
        addrs: not_exit.handle.listen_addrs().await.unwrap(),
        blocked_tcp_ports: vec![],
        kind: ExitKind::Dedicated,
        expires_at: now_secs() + 600,
    };
    let result = client.handle.open_circuit_via(relay.handle.peer_id(), &target).await;
    assert!(matches!(result, Err(CircuitError::ExitUnreachable)), "got {:?}", result.err());

    // And it never shows up as an exit in the DHT.
    let exits = client.handle.find_exits().await.unwrap();
    assert!(exits.iter().all(|r| r.peer_id != not_exit.handle.peer_id()));
}

#[tokio::test]
async fn node_without_relay_refuses_to_splice() {
    let (_boot, _relay, exit, client) = network().await;
    let record = exit_record_of(&client, &exit).await;

    // The exit runs with relaying disabled, so it can't be used as an entry.
    let result = client.handle.open_circuit_via(exit.handle.peer_id(), &record).await;
    assert!(matches!(result, Err(CircuitError::RelayRefused)), "got {:?}", result.err());
}

#[tokio::test]
async fn relay_refuses_to_splice_back_to_the_client() {
    let (_boot, relay, _exit, client) = network().await;
    let identity = Identity::load(&client.data_dir).unwrap();
    let loopback = ExitRecord {
        peer_id: client.handle.peer_id(),
        noise_static: identity.exit_static.public,
        addrs: vec![],
        blocked_tcp_ports: vec![],
        kind: ExitKind::Dedicated,
        expires_at: now_secs() + 600,
    };
    let result = client.handle.open_circuit_via(relay.handle.peer_id(), &loopback).await;
    assert!(matches!(result, Err(CircuitError::RelayRefused)), "got {:?}", result.err());
}
