//! Exit selection (docs/DESIGN.md §3.10) on real nodes: dedicated exits before other
//! users' exits, and max-ping mode measuring latency through test circuits.

mod common;

use std::time::Duration;

use common::{Opts, TestNode, run_exit_forwarder, start, wait_for};
use dvpn::records::{ExitKind, ExitRecord};
use dvpn::select::{self, Selection};
use libp2p::PeerId;

/// Bootstrap + relay + the given exits + a client that has found all of them.
async fn network(exit_kinds: &[ExitKind]) -> (Vec<TestNode>, Vec<TestNode>, TestNode, Vec<ExitRecord>, Vec<PeerId>) {
    let boot = start(Opts::default()).await;
    let via_boot = || vec![boot.addr.clone().unwrap()];
    let relay = start(Opts {
        bootstrap: via_boot(),
        relay: true,
        ..Default::default()
    })
    .await;
    let mut exits = Vec::new();
    for &kind in exit_kinds {
        let mut exit = start(Opts {
            bootstrap: via_boot(),
            exit: true,
            exit_kind: kind,
            ..Default::default()
        })
        .await;
        run_exit_forwarder(&mut exit);
        exits.push(exit);
    }
    let client = start(Opts {
        bootstrap: via_boot(),
        ..Default::default()
    })
    .await;
    let records = wait_for("every exit record", || async {
        let records = client.handle.find_exits().await.ok()?;
        (records.len() == exit_kinds.len()).then_some(records)
    })
    .await;
    let relays = wait_for("the relay", || async {
        let relays = client.handle.find_relays().await.ok()?;
        (!relays.is_empty()).then_some(relays)
    })
    .await;
    // Relay addresses must be known before circuits can go through it.
    wait_for("relay address", || async {
        (!client.handle.peer_addrs(relay.handle.peer_id()).await.ok()?.is_empty()).then_some(())
    })
    .await;
    (vec![boot, relay], exits, client, records, relays)
}

fn kind_of(records: &[ExitRecord], exit: PeerId) -> ExitKind {
    records.iter().find(|r| r.peer_id == exit).unwrap().kind
}

#[tokio::test]
async fn random_mode_never_uses_another_users_exit_while_a_dedicated_one_works() {
    let (_infra, _exits, client, records, relays) =
        network(&[ExitKind::Dedicated, ExitKind::User, ExitKind::User]).await;
    for _ in 0..6 {
        let (circuit, report) = select::open(&client.handle, records.clone(), relays.clone(), Selection::Random, &|_, _| Ok(())).await;
        let circuit = circuit.unwrap();
        assert_eq!(kind_of(&records, circuit.exit), ExitKind::Dedicated);
        assert!(report.is_none(), "random mode measures nothing");
    }
}

#[tokio::test]
async fn another_users_exit_is_used_when_it_is_the_only_way() {
    let (_infra, _exits, client, records, relays) = network(&[ExitKind::User]).await;
    let (circuit, _) = select::open(&client.handle, records.clone(), relays, Selection::Random, &|_, _| Ok(())).await;
    assert_eq!(kind_of(&records, circuit.unwrap().exit), ExitKind::User);
}

#[tokio::test]
async fn max_ping_measures_exits_and_picks_one_within_the_limit() {
    let (_infra, _exits, client, records, relays) =
        network(&[ExitKind::Dedicated, ExitKind::Dedicated, ExitKind::User]).await;

    let generous = Selection::MaxPing(Duration::from_secs(5));
    let (circuit, report) = select::open(&client.handle, records.clone(), relays.clone(), generous, &|_, _| Ok(())).await;
    let mut circuit = circuit.unwrap();
    let report = report.unwrap();
    assert_eq!(kind_of(&records, circuit.exit), ExitKind::Dedicated);
    assert_eq!((report.measured, report.within_limit), (2, 2), "{report}");
    assert!(!report.used_user_exits);
    assert!(report.fastest_ms.unwrap() <= 5000);

    // The chosen test circuit is the connection: still alive and answering.
    let rtt = select::measure_rtt(&mut circuit.tunnel, Duration::from_secs(2)).await;
    assert!(rtt.is_some(), "the picked circuit was closed");
}

#[tokio::test]
async fn max_ping_reports_when_no_exit_is_fast_enough() {
    let (_infra, _exits, client, records, relays) = network(&[ExitKind::Dedicated, ExitKind::User]).await;

    // No real path is this fast, so nothing qualifies, in either tier.
    let impossible = Selection::MaxPing(Duration::from_nanos(1));
    let (circuit, report) = select::open(&client.handle, records, relays, impossible, &|_, _| Ok(())).await;
    let error = circuit.err().expect("connected despite an impossible limit");
    let report = report.unwrap();
    assert_eq!(report.within_limit, 0);
    assert_eq!(report.measured, 2, "both tiers are measured before giving up: {report}");
    assert!(report.used_user_exits);
    assert!(report.fastest_ms.is_some(), "the fastest measured exit is reported");
    assert!(format!("{error:#}").contains("no exit within"), "{error:#}");
}

#[tokio::test]
async fn max_ping_falls_back_to_other_users_exits_only_without_a_dedicated_one() {
    let (_infra, _exits, client, records, relays) = network(&[ExitKind::User, ExitKind::User]).await;
    let (circuit, report) = select::open(
        &client.handle,
        records.clone(),
        relays,
        Selection::MaxPing(Duration::from_secs(5)),
        &|_, _| Ok(()),
    )
    .await;
    assert_eq!(kind_of(&records, circuit.unwrap().exit), ExitKind::User);
    assert!(report.unwrap().used_user_exits);
}
