//! Multi-node discovery tests on localhost. mDNS is disabled so discovery must go
//! through bootstrap addresses, the DHT and the peer cache.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Opts, TestNode, start, start_in, wait_for};
use libp2p::PeerId;

async fn wait_until_knows(node: &TestNode, expected: &[PeerId]) {
    wait_for(&format!("{} to discover {expected:?}", node.handle.peer_id()), || async {
        let known = node.handle.routing_peers().await.unwrap();
        expected.iter().all(|p| known.contains(p)).then_some(())
    })
    .await;
}

#[tokio::test]
async fn three_nodes_discover_each_other_via_dht() {
    // Chain: B knows only A, C knows only B. C must learn about A through the DHT.
    let a = start(Opts::default()).await;
    let b = start(Opts {
        bootstrap: vec![a.addr.clone().unwrap()],
        ..Default::default()
    })
    .await;
    let c = start(Opts {
        bootstrap: vec![b.addr.clone().unwrap()],
        ..Default::default()
    })
    .await;
    let (a_id, b_id, c_id) = (a.handle.peer_id(), b.handle.peer_id(), c.handle.peer_id());

    wait_until_knows(&c, &[a_id, b_id]).await;
    wait_until_knows(&a, &[b_id, c_id]).await;
    wait_until_knows(&b, &[a_id, c_id]).await;
}

#[tokio::test]
async fn restarted_node_rejoins_from_peer_cache() {
    let a = start(Opts::default()).await;
    let tmp_b = tempfile::tempdir().unwrap();
    let b = start_in(
        tmp_b.path(),
        Opts {
            bootstrap: vec![a.addr.clone().unwrap()],
            ..Default::default()
        },
    )
    .await;
    wait_until_knows(&b, &[a.handle.peer_id()]).await;
    b.handle.shutdown().await.unwrap();

    let cache = b.data_dir.join("peers.json");
    let mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "peer cache must be private");

    // No bootstrap address this time: the cache alone must get B back into the network.
    let b = start_in(tmp_b.path(), Opts::default()).await;
    wait_until_knows(&b, &[a.handle.peer_id()]).await;
    wait_until_knows(&a, &[b.handle.peer_id()]).await;
}
