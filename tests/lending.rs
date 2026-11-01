//! Lend to use (docs/DESIGN.md §3.9): when lending counts as ready, and that the client
//! refuses to connect, and waits, until it is.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Duration;

use common::{Opts, start, wait_for};
use dvpn::circuit::IpPool;
use dvpn::client::{self, ConnectOptions};
use dvpn::control::{Phase, SharedState};
use dvpn::lend::{LendingHandle, lending_ready};
use dvpn::node::{NatState, Reachability};

fn lending_handle(forwarder_alive: bool) -> LendingHandle {
    LendingHandle {
        active: Arc::new(AtomicUsize::new(0)),
        max_sessions: 16,
        alive: Arc::new(AtomicBool::new(forwarder_alive)),
        pool: IpPool::default(),
        wan: "eth0".into(),
        rate_mbps: 10,
    }
}

fn connect_options() -> ConnectOptions {
    ConnectOptions {
        tun_name: "dvpn-test0".into(),
        dns: None,
    }
}

#[tokio::test]
async fn a_public_exit_is_ready_once_its_record_is_published() {
    let boot = start(Opts::default()).await;
    let exit = start(Opts {
        bootstrap: vec![boot.addr.clone().unwrap()],
        exit: true,
        ..Default::default()
    })
    .await;
    let not_exit = start(Opts {
        bootstrap: vec![boot.addr.clone().unwrap()],
        ..Default::default()
    })
    .await;

    let status = wait_for("the exit record to be published", || async {
        let status = exit.handle.status().await.ok()?;
        status.exit_published.then_some(status)
    })
    .await;
    assert!(lending_ready(&status, true));
    assert!(!lending_ready(&status, false), "a stopped forwarder is not lending");

    let other = not_exit.handle.status().await.unwrap();
    assert!(!other.exit_published && !lending_ready(&other, true), "only exits lend");
}

#[tokio::test]
async fn an_exit_behind_nat_is_ready_through_a_relay_reservation() {
    let relay = start(Opts {
        relay: true,
        ..Default::default()
    })
    .await;
    let natted = start(Opts {
        bootstrap: vec![relay.addr.clone().unwrap()],
        reachability: Reachability::Auto,
        exit: true,
        listen: false,
        ..Default::default()
    })
    .await;
    assert!(!lending_ready(&natted.handle.status().await.unwrap(), true), "ready before anyone can reach it");

    let status = wait_for("lending through a relay", || async {
        let status = natted.handle.status().await.ok()?;
        lending_ready(&status, true).then_some(status)
    })
    .await;
    assert_eq!(status.nat, NatState::Private);
    assert!(status.relay_reservations >= 1);
    assert!(!status.publicly_reachable);
}

#[tokio::test]
async fn connect_refuses_to_run_without_lending() {
    let node = start(Opts::default()).await;
    let error = client::run(node.handle.clone(), connect_options(), SharedState::default())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("requires lending"), "{error:#}");
}

#[tokio::test]
async fn connect_builds_no_circuit_until_lending_is_ready() {
    // A complete network with an exit and a relay is available...
    let boot = start(Opts::default()).await;
    let via_boot = || vec![boot.addr.clone().unwrap()];
    let _relay = start(Opts {
        bootstrap: via_boot(),
        relay: true,
        ..Default::default()
    })
    .await;
    let _exit = start(Opts {
        bootstrap: via_boot(),
        exit: true,
        ..Default::default()
    })
    .await;
    // ...but this client's own exit isn't lending (its forwarder is down).
    let client = start(Opts {
        bootstrap: via_boot(),
        exit: true,
        ..Default::default()
    })
    .await;
    wait_for("the client's exit record", || async {
        client.handle.status().await.ok()?.exit_published.then_some(())
    })
    .await;

    let state = SharedState {
        lending: Some(lending_handle(false)),
        ..SharedState::default()
    };
    let run = client::run(client.handle.clone(), connect_options(), state.clone());
    let outcome = tokio::time::timeout(Duration::from_secs(8), run).await;
    assert!(outcome.is_err(), "client::run returned: {:?}", outcome.map(|r| r.map_err(|e| format!("{e:#}"))));
    assert_eq!(*state.phase.lock().unwrap(), Phase::WaitingForLending);
    assert!(state.circuit.lock().unwrap().is_none());
}
