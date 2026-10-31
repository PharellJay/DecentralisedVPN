//! NAT traversal without root: AutoNAT detection and Circuit Relay v2 reachability.
//!
//! A node that doesn't listen at all stands in for a node behind NAT: it can only make
//! outbound connections, so AutoNAT dial-backs fail exactly as they would through NAT.
//! Real hole punching (DCUtR) needs actual NATs and is covered by the M3 netns harness.

mod common;

use common::{Opts, start, wait_for};
use dvpn::addrs::is_circuit;
use dvpn::node::{NatState, Reachability};

#[tokio::test]
async fn autonat_confirms_a_reachable_node_as_public() {
    let a = start(Opts::default()).await;
    let b = start(Opts {
        bootstrap: vec![a.addr.clone().unwrap()],
        ..Default::default()
    })
    .await;
    let node = start(Opts {
        bootstrap: vec![a.addr.clone().unwrap(), b.addr.clone().unwrap()],
        reachability: Reachability::Auto,
        ..Default::default()
    })
    .await;

    wait_for("AutoNAT to report Public", || async {
        (node.handle.status().await.ok()?.nat == NatState::Public).then_some(())
    })
    .await;
}

#[tokio::test]
async fn node_behind_nat_reserves_a_relay_and_is_reachable_through_it() {
    let relay = start(Opts {
        relay: true,
        ..Default::default()
    })
    .await;
    let natted = start(Opts {
        bootstrap: vec![relay.addr.clone().unwrap()],
        reachability: Reachability::Auto,
        listen: false,
        ..Default::default()
    })
    .await;

    let status = wait_for("NAT detection and relay reservation", || async {
        let status = natted.handle.status().await.ok()?;
        (status.nat == NatState::Private && status.relay_reservations >= 1).then_some(status)
    })
    .await;
    assert!(status.external_addrs.iter().all(is_circuit), "only relayed addresses expected");

    // A third node with no prior contact reaches the NATed node via the relay.
    let outsider = start(Opts {
        bootstrap: vec![relay.addr.clone().unwrap()],
        ..Default::default()
    })
    .await;
    let circuit_addr = natted
        .handle
        .listen_addrs()
        .await
        .unwrap()
        .into_iter()
        .find(is_circuit)
        .expect("relayed listen address"); // already ends in /p2p/<natted>
    let connected_via = outsider
        .handle
        .dial(natted.handle.peer_id(), vec![circuit_addr], true)
        .await
        .unwrap();
    assert!(is_circuit(&connected_via), "connected via {connected_via}, expected a relay circuit");
}

#[tokio::test]
async fn exit_behind_nat_serves_circuits() {
    let boot = start(Opts {
        relay: true,
        ..Default::default()
    })
    .await;
    let via_boot = || vec![boot.addr.clone().unwrap()];
    let entry = start(Opts {
        bootstrap: via_boot(),
        relay: true,
        ..Default::default()
    })
    .await;
    let mut exit = start(Opts {
        bootstrap: via_boot(),
        reachability: Reachability::Auto,
        listen: false,
        exit: true,
        ..Default::default()
    })
    .await;
    let client = start(Opts {
        bootstrap: via_boot(),
        ..Default::default()
    })
    .await;

    // The exit can only advertise relayed addresses.
    let record = wait_for("NATed exit's record", || async {
        let exits = client.handle.find_exits().await.ok()?;
        exits.into_iter().find(|r| r.peer_id == exit.handle.peer_id() && !r.addrs.is_empty())
    })
    .await;
    assert!(record.addrs.iter().all(is_circuit), "exit advertised {:?}", record.addrs);

    let mut circuit = wait_for("circuit to the NATed exit", || async {
        client.handle.open_circuit_via(entry.handle.peer_id(), &record).await.ok()
    })
    .await;
    let mut session = exit.exit_sessions.as_mut().unwrap().recv().await.unwrap();
    assert_eq!(session.via_peer, entry.handle.peer_id());

    circuit.tunnel.tx.send(b"ping through NAT").await.unwrap();
    assert_eq!(session.tunnel.rx.recv().await.unwrap().unwrap(), b"ping through NAT");
    session.tunnel.tx.send(b"pong").await.unwrap();
    assert_eq!(circuit.tunnel.rx.recv().await.unwrap().unwrap(), b"pong");
}
