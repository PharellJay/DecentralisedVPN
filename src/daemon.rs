//! `dvpn daemon`: the background service behind the desktop app.
//!
//! It runs under systemd (`packaging/dvpn.service`, started at boot) as the user `dvpn`
//! with CAP_NET_ADMIN, not as root, and does
//! nothing on the network until a client asks it to lend or connect, or, with lending
//! at boot on, until it has started lending by itself. Clients talk to it over
//! [`SERVICE_SOCKET`]. Anyone can open the socket, but the service answers only users
//! the platform allows ([`Access`]; on Linux: root, people signed in at this computer,
//! and members of the `dvpn` group). Requests can only pick from the fixed set of
//! [`Action`]s; no paths, commands or system settings pass through the socket.
//!
//! On SIGTERM (`systemctl stop dvpn`) it disconnects and stops lending, restoring routes
//! and the firewall, before exiting.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::control::{self, Authorize, Feed, Handler, Request, Response};
use crate::controller::{Action, Controller};
use crate::platform::ipc::{self, Listener, Stream};
pub use crate::platform::service::{Access, SERVICE_DATA_DIR, SERVICE_SOCKET, listen, permission_help};

/// How often finished background work is collected while no client asks, and how often
/// watchers' state is refreshed.
const POLL: Duration = Duration::from_secs(1);
/// With lending at boot on: how long to wait before starting lending again after it
/// failed (e.g. no network yet) or stopped.
pub const LEND_AT_BOOT_RETRY: Duration = Duration::from_secs(30);

/// Serves `controller` on `listener` until `shutdown` completes, then turns everything off.
pub async fn run(mut controller: Controller, listener: Listener, shutdown: impl Future<Output = ()>) {
    let (tx, mut requests) = mpsc::channel::<(Request, oneshot::Sender<Response>)>(16);
    let handler: Handler = Arc::new(move |request| {
        let tx = tx.clone();
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            if tx.send((request, reply)).await.is_err() {
                return Response::Error("dvpn is shutting down".into());
            }
            answer.await.unwrap_or_else(|_| Response::Error("dvpn is shutting down".into()))
        })
    });
    let access = Arc::new(Access::default());
    let authorize: Authorize = Arc::new(move |peer| access.check(peer));
    let feed = Feed::new(controller.logs());
    let server = tokio::spawn(control::serve_with(listener, handler, Some(authorize), Some(feed.clone())));
    // When to (re)start lending by itself; `None` once the user turns it off.
    let mut lend_at = controller.lend_at_boot().then(Instant::now);
    match lend_at {
        Some(_) => info!("dvpn service ready; lending at boot is on"),
        None => info!("dvpn service ready; idle until a client asks it to lend or connect"),
    }

    tokio::pin!(shutdown);
    let mut poll = tokio::time::interval(POLL);
    loop {
        tokio::select! {
            Some((request, reply)) = requests.recv() => {
                controller.poll().await;
                // Turning off (or turning lending at boot off) also stops restarting it.
                if matches!(request, Request::Act(Action::Stop | Action::SetLendAtBoot { enabled: false })) {
                    lend_at = None;
                }
                let response = answer(&mut controller, request).await;
                if let Response::View(view) = &response {
                    feed.publish((**view).clone());
                } else {
                    refresh(&controller, &feed).await;
                }
                let _ = reply.send(response);
            }
            _ = poll.tick() => {
                controller.poll().await;
                keep_lending(&mut controller, &mut lend_at).await;
                refresh(&controller, &feed).await;
            }
            () = &mut shutdown => break,
        }
    }
    server.abort();
    info!("stopping: disconnecting and restoring the network");
    controller.stop().await;
}

/// Keeps watchers' state current, while there are any.
async fn refresh(controller: &Controller, feed: &Feed) {
    if feed.watched()
        && let Ok(view) = controller.view_with(false).await
    {
        feed.publish(view);
    }
}

/// With lending at boot on, starts lending, and starts it again if it fails (the network
/// may not be up yet at boot) or the node stops later.
async fn keep_lending(controller: &mut Controller, lend_at: &mut Option<Instant>) {
    let Some(at) = *lend_at else {
        return;
    };
    if controller.is_running() || Instant::now() < at {
        return;
    }
    if !controller.consent_given() {
        info!("lending at boot waits until the lending terms are accepted");
        *lend_at = None;
        return;
    }
    match controller.start().await {
        Ok(()) => info!("lending at boot: started"),
        Err(e) => warn!("lending at boot: {e:#}; trying again in {} s", LEND_AT_BOOT_RETRY.as_secs()),
    }
    *lend_at = Some(Instant::now() + LEND_AT_BOOT_RETRY);
}

async fn answer(controller: &mut Controller, request: Request) -> Response {
    match request {
        // Served by the control socket from the feed.
        Request::Watch { .. } => Response::Error("not available here".into()),
        Request::Status => match controller.status().await {
            Ok(report) => Response::Status(Box::new(report)),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::View => match controller.view().await {
            Ok(view) => Response::View(Box::new(view)),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::Act(action) => {
            info!("client asked: {}", action_name(&action));
            let result = controller.act(action).await;
            if let Err(e) = &result {
                warn!("{e:#}");
            }
            Response::from_result(result)
        }
    }
}

/// For the log, without arguments (bootstrap addresses are never logged).
fn action_name(action: &Action) -> &'static str {
    match action {
        Action::AcceptExitRisk => "accept the lending terms",
        Action::Lend => "lend without connecting",
        Action::Connect => "connect",
        Action::Disconnect => "disconnect",
        Action::Stop => "turn off",
        Action::SetSelection { max_ping_ms: None } => "random exits",
        Action::SetSelection { max_ping_ms: Some(_) } => "max-ping exits",
        Action::Measure => "measure exits",
        Action::AddBootstrap { .. } => "add a bootstrap peer",
        Action::RemoveBootstrap { .. } => "remove a bootstrap peer",
        Action::SetLendAtBoot { enabled: true } => "lend at boot",
        Action::SetLendAtBoot { enabled: false } => "don't lend at boot",
    }
}

/// Whether the service can be reached at `path` by this user.
pub enum Probe {
    Available(Stream),
    /// The service is there, but this user isn't allowed to control it.
    PermissionDenied,
    /// Not installed, or not running.
    Absent,
}

pub async fn probe(path: &Path) -> Probe {
    match ipc::connect(path).await {
        Ok(stream) => Probe::Available(stream),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Probe::PermissionDenied,
        Err(_) => Probe::Absent,
    }
}
