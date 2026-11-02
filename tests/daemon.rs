//! The service (`dvpn daemon`) over its control socket, without root: lending can't
//! start here, which is reported to the client instead of taking the service down.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dvpn::config::FileConfig;
use dvpn::control::{Client, Request, Response};
use dvpn::controller::{Action, Controller, StartFn};
use dvpn::daemon;
use dvpn::logs::LogBuffer;
use dvpn::select::Selection;
use tokio::sync::oneshot;

const BOOTSTRAP: &str = "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

#[tokio::test]
async fn service_takes_actions_and_reports_failures_to_clients() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let socket = dir.path().join("run/control.sock");

    let starts = Arc::new(AtomicUsize::new(0));
    let start: StartFn = Box::new({
        let starts = starts.clone();
        move || {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { anyhow::bail!("creating the exit TUN device: needs root") })
        }
    });
    let controller = Controller::new(&data_dir, "12D3KooWTest".into(), Selection::Random, LogBuffer::default(), start);
    let listener = daemon::listen(&socket).await.unwrap();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "only root and the dvpn group may control the service");

    let (stop, stopped) = oneshot::channel::<()>();
    let service = tokio::spawn(daemon::run(controller, listener, async {
        let _ = stopped.await;
    }));

    let mut client = Client::connect(&socket).await.unwrap();
    let view = client.view().await.unwrap();
    assert!(!view.consent_given);
    assert!(!view.running, "the service starts idle");

    // Nothing starts before the lending terms are accepted, not even lending alone.
    let refused = client.act(Action::Connect).await.unwrap_err();
    assert!(refused.to_string().contains("lending terms"), "{refused}");
    let refused = client.act(Action::Lend).await.unwrap_err();
    assert!(refused.to_string().contains("lending terms"), "{refused}");
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    client.act(Action::AcceptExitRisk).await.unwrap();
    assert!(client.view().await.unwrap().consent_given);

    // A failed start is the client's error, and the service keeps serving.
    let failed = client.act(Action::Connect).await.unwrap_err();
    assert!(failed.to_string().contains("needs root"), "{failed}");
    let view = client.view().await.unwrap();
    assert!(!view.running);
    assert!(view.error.unwrap().contains("needs root"));

    // Lending on its own starts the same session, without the VPN.
    let failed = client.act(Action::Lend).await.unwrap_err();
    assert!(failed.to_string().contains("needs root"), "{failed}");
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert!(!client.view().await.unwrap().vpn.running);
    match client.send(&Request::Status).await.unwrap() {
        Response::Error(e) => assert!(e.contains("idle"), "{e}"),
        other => panic!("unexpected {other:?}"),
    }

    // Selection is kept while idle, with its limit clamped.
    client.act(Action::SetSelection { max_ping_ms: Some(999_999) }).await.unwrap();
    let view = client.view().await.unwrap();
    assert_eq!(view.selection, Selection::MaxPing(std::time::Duration::from_secs(60)));
    assert_eq!(view.ping_limit_ms, 60_000);

    // Bootstrap peers are validated and saved once.
    assert!(client.act(Action::AddBootstrap { addr: "/ip4/203.0.113.7/tcp/4001".into() }).await.is_err());
    client.act(Action::AddBootstrap { addr: BOOTSTRAP.into() }).await.unwrap();
    client.act(Action::AddBootstrap { addr: BOOTSTRAP.into() }).await.unwrap();
    assert_eq!(FileConfig::load(&data_dir).unwrap().bootstrap, [BOOTSTRAP]);

    // Several clients at once; garbage gets an error, not a crash.
    let mut second = Client::connect(&socket).await.unwrap();
    assert!(second.view().await.is_ok());
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut raw = tokio::net::UnixStream::connect(&socket).await.unwrap();
        raw.write_all(b"{\"cmd\":\"act\",\"action\":\"format_disk\"}\n").await.unwrap();
        let mut line = String::new();
        BufReader::new(&mut raw).read_line(&mut line).await.unwrap();
        assert!(line.contains("invalid request"), "{line}");
    }
    assert!(client.view().await.is_ok());

    stop.send(()).unwrap();
    service.await.unwrap();
}

/// A service whose every start fails (lending needs root), counting the attempts.
async fn failing_service(
    data_dir: &std::path::Path,
    socket: &std::path::Path,
) -> (Arc<AtomicUsize>, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let starts = Arc::new(AtomicUsize::new(0));
    let start: StartFn = Box::new({
        let starts = starts.clone();
        move || {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { anyhow::bail!("creating the exit TUN device: needs root") })
        }
    });
    let controller = Controller::new(data_dir, "12D3KooWTest".into(), Selection::Random, LogBuffer::default(), start);
    let listener = daemon::listen(socket).await.unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let service = tokio::spawn(daemon::run(controller, listener, async {
        let _ = stopped.await;
    }));
    (starts, stop, service)
}

#[tokio::test]
async fn service_lends_at_boot_when_set() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let socket = dir.path().join("run/control.sock");
    dvpn::lend::record_consent(&data_dir).unwrap();
    FileConfig { lend_at_boot: true, ..FileConfig::default() }.save(&data_dir).unwrap();

    let (starts, stop, service) = failing_service(&data_dir, &socket).await;
    // It tries to lend as soon as it starts, without any client asking.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while starts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the service never tried to lend");

    let mut client = Client::connect(&socket).await.unwrap();
    let view = client.view().await.unwrap();
    assert!(view.lend_at_boot);
    assert!(!view.running);
    assert!(view.error.unwrap().contains("needs root"), "the failure is shown to clients");

    // The setting is saved, and turning it off doesn't touch the bootstrap peers.
    client.act(Action::AddBootstrap { addr: BOOTSTRAP.into() }).await.unwrap();
    client.act(Action::SetLendAtBoot { enabled: false }).await.unwrap();
    let saved = FileConfig::load(&data_dir).unwrap();
    assert!(!saved.lend_at_boot);
    assert_eq!(saved.bootstrap, [BOOTSTRAP]);
    assert!(!client.view().await.unwrap().lend_at_boot);
    client.act(Action::SetLendAtBoot { enabled: true }).await.unwrap();
    assert!(FileConfig::load(&data_dir).unwrap().lend_at_boot);

    stop.send(()).unwrap();
    service.await.unwrap();
}

#[tokio::test]
async fn lending_at_boot_needs_the_terms() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let socket = dir.path().join("run/control.sock");
    // Set by hand, without the terms accepted.
    FileConfig { lend_at_boot: true, ..FileConfig::default() }.save(&data_dir).unwrap();

    let (starts, stop, service) = failing_service(&data_dir, &socket).await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0, "nothing starts before the terms are accepted");

    let mut client = Client::connect(&socket).await.unwrap();
    let refused = client.act(Action::SetLendAtBoot { enabled: true }).await.unwrap_err();
    assert!(refused.to_string().contains("lending terms"), "{refused}");
    client.act(Action::SetLendAtBoot { enabled: false }).await.unwrap();

    stop.send(()).unwrap();
    service.await.unwrap();
}
