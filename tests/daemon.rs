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
    // Only what clients ask for: lending at boot (on by default) would race the counts below.
    FileConfig { lend_at_boot: false, ..FileConfig::default() }.save(&data_dir).unwrap();

    let starts = Arc::new(AtomicUsize::new(0));
    let start: StartFn = Box::new({
        let starts = starts.clone();
        move || {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { anyhow::bail!("creating the exit TUN device: needs root") })
        }
    });
    let controller = Controller::new(&data_dir, Selection::Random, LogBuffer::default(), start);
    let listener = daemon::listen(&socket).await.unwrap();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666, "anyone may connect; the service decides whom it answers");

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
    assert_eq!(client.view().await.unwrap().bootstrap, [BOOTSTRAP], "listed in the app");
    client.act(Action::RemoveBootstrap { addr: BOOTSTRAP.into() }).await.unwrap();
    assert!(FileConfig::load(&data_dir).unwrap().bootstrap.is_empty());
    assert!(client.view().await.unwrap().bootstrap.is_empty());

    // An invite link adds all its peers at once.
    let other = "/ip4/198.51.100.3/udp/4001/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
    let link = format!("dvpn://join?peer={BOOTSTRAP}&peer={other}");
    client.act(Action::AddBootstrap { addr: link }).await.unwrap();
    assert_eq!(FileConfig::load(&data_dir).unwrap().bootstrap, [BOOTSTRAP, other]);
    client.act(Action::RemoveBootstrap { addr: other.into() }).await.unwrap();
    client.act(Action::RemoveBootstrap { addr: BOOTSTRAP.into() }).await.unwrap();

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
    let controller = Controller::new(data_dir, Selection::Random, LogBuffer::default(), start);
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

#[tokio::test]
async fn watchers_get_changes_and_new_log_lines_pushed() {
    use std::io::Write;
    use std::time::Duration;
    use tracing_subscriber::fmt::MakeWriter;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let socket = dir.path().join("run/control.sock");
    FileConfig { lend_at_boot: false, ..FileConfig::default() }.save(&data_dir).unwrap();
    let logs = LogBuffer::default();
    writeln!(logs.make_writer(), "before watching").unwrap();
    let start: StartFn = Box::new(|| Box::pin(async { anyhow::bail!("needs root") }));
    let controller = Controller::new(&data_dir, Selection::Random, logs.clone(), start);
    let listener = daemon::listen(&socket).await.unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let service = tokio::spawn(daemon::run(controller, listener, async {
        let _ = stopped.await;
    }));

    // First: the whole state, and the recent log.
    let mut watcher = Client::connect(&socket).await.unwrap().watch(true).await.unwrap();
    let first = next(&mut watcher).await;
    let view = first.view.expect("the state comes first");
    assert_eq!(view.selection, Selection::Random);
    assert!(view.logs.is_empty(), "log lines come separately");
    assert_eq!(first.logs, ["before watching"]);

    // A change made by another client is pushed, without asking.
    let mut client = Client::connect(&socket).await.unwrap();
    client.act(Action::SetSelection { max_ping_ms: Some(80) }).await.unwrap();
    let changed = loop {
        if let Some(view) = next(&mut watcher).await.view {
            break view;
        }
    };
    assert_eq!(changed.selection, Selection::MaxPing(Duration::from_millis(80)));

    // New log lines arrive on their own, each once.
    writeln!(logs.make_writer(), "a new line").unwrap();
    let mut received = Vec::new();
    while !received.iter().any(|l: &String| l == "a new line") {
        received.extend(next(&mut watcher).await.logs);
    }
    assert_eq!(received.iter().filter(|l| *l == "a new line").count(), 1);
    assert!(!received.iter().any(|l| l == "before watching"), "old lines aren't sent again");

    // A watcher that goes away doesn't disturb the service.
    drop(watcher);
    assert!(client.view().await.is_ok());

    stop.send(()).unwrap();
    service.await.unwrap();
}

async fn next(watcher: &mut dvpn::control::Watcher) -> dvpn::control::Update {
    tokio::time::timeout(std::time::Duration::from_secs(5), watcher.next()).await.expect("no update").unwrap()
}
