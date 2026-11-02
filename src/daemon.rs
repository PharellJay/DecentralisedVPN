//! `dvpn daemon`: the background service behind the desktop app and the unprivileged
//! dashboard.
//!
//! It runs as root (under systemd, `packaging/dvpn.service`, started at boot) and does
//! nothing on the network until a client asks it to lend or connect, or, with lending
//! at boot on, until it has started lending by itself. Clients talk to it over
//! [`SERVICE_SOCKET`], which only root and members of the [`SERVICE_GROUP`] group can
//! open; that group is what grants a user control over the VPN. Requests can only pick
//! from the fixed set of [`Action`]s; no paths, commands or system settings pass
//! through the socket.
//!
//! On SIGTERM (`systemctl stop dvpn`) it disconnects and stops lending, restoring routes
//! and the firewall, before exiting.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::control::{self, Handler, Request, Response};
use crate::controller::{Action, Controller};

pub const SERVICE_SOCKET: &str = "/run/dvpn/control.sock";
pub const SERVICE_DATA_DIR: &str = "/var/lib/dvpn";
pub const SERVICE_GROUP: &str = "dvpn";
/// How often finished background work is collected while no client asks.
const POLL: Duration = Duration::from_secs(1);
/// With lending at boot on: how long to wait before starting lending again after it
/// failed (e.g. no network yet) or stopped.
pub const LEND_AT_BOOT_RETRY: Duration = Duration::from_secs(30);
/// First file descriptor passed by systemd socket activation.
const SD_LISTEN_FDS_START: i32 = 3;

/// Serves `controller` on `listener` until `shutdown` completes, then turns everything off.
pub async fn run(mut controller: Controller, listener: UnixListener, shutdown: impl Future<Output = ()>) {
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
    let server = tokio::spawn(control::serve_with(listener, handler));
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
                let _ = reply.send(response);
            }
            _ = poll.tick() => {
                controller.poll().await;
                keep_lending(&mut controller, &mut lend_at).await;
            }
            () = &mut shutdown => break,
        }
    }
    server.abort();
    info!("stopping: disconnecting and restoring the network");
    controller.stop().await;
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
        warn!("lending at boot is on, but the lending terms haven't been accepted yet");
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
        Action::SetLendAtBoot { enabled: true } => "lend at boot",
        Action::SetLendAtBoot { enabled: false } => "don't lend at boot",
    }
}

/// The socket systemd passed (socket activation), or a new one bound at `path`, owned
/// by `root:dvpn` with mode 0660.
pub async fn listen(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(listener) = systemd_listener()? {
        return Ok(listener);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let listener = control::bind_path(path, 0o660).await?;
    match group_id(SERVICE_GROUP) {
        // Only the group: the owner is whoever created the socket, root for the service.
        Some(gid) => std::os::unix::fs::chown(path, None, Some(gid)).context("setting the socket's group")?,
        None => warn!("there is no `{SERVICE_GROUP}` group, so only root can use {}", path.display()),
    }
    Ok(listener)
}

/// Takes the first socket passed with `LISTEN_FDS`, if it was passed to this process.
fn systemd_listener() -> anyhow::Result<Option<UnixListener>> {
    use std::os::fd::FromRawFd;
    let ours = std::env::var("LISTEN_PID").ok().and_then(|p| p.parse::<u32>().ok()) == Some(std::process::id());
    let count = std::env::var("LISTEN_FDS").ok().and_then(|n| n.parse::<i32>().ok()).unwrap_or(0);
    if !ours || count < 1 {
        return Ok(None);
    }
    // SAFETY: systemd hands this process fd 3 as the listening socket of dvpn.socket,
    // and nothing else in the process uses it.
    let passed = unsafe { std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };
    // The passed fd is inherited by child processes (`ip`, `nft`); its clone is not
    // (close-on-exec), so keep the clone and close the original.
    let listener = passed.try_clone().context("taking over the systemd socket")?;
    drop(passed);
    listener.set_nonblocking(true)?;
    info!("using the control socket passed by systemd");
    Ok(Some(UnixListener::from_std(listener)?))
}

/// Looks `name` up in /etc/group (where systemd-sysusers and groupadd put it).
fn group_id(name: &str) -> Option<u32> {
    parse_group_id(&std::fs::read_to_string("/etc/group").ok()?, name)
}

fn parse_group_id(group_file: &str, name: &str) -> Option<u32> {
    group_file.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

/// Whether the service can be reached at `path` by this user.
pub enum Probe {
    Available(UnixStream),
    /// The service is there, but this user isn't allowed to control it.
    PermissionDenied,
    /// Not installed, or not running.
    Absent,
}

pub async fn probe(path: &Path) -> Probe {
    match UnixStream::connect(path).await {
        Ok(stream) => Probe::Available(stream),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Probe::PermissionDenied,
        Err(_) => Probe::Absent,
    }
}

pub fn permission_help() -> String {
    format!(
        "the dvpn service is running, but this account can't control it.\n\
         Add yourself to the `{SERVICE_GROUP}` group, then log out and back in:\n\n    \
         sudo usermod -aG {SERVICE_GROUP} $USER"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_group_ids() {
        let file = "root:x:0:\nsudo:x:27:alice\ndvpn:x:998:alice,bob\ndvpnx:x:5:\n";
        assert_eq!(parse_group_id(file, "dvpn"), Some(998));
        assert_eq!(parse_group_id(file, "root"), Some(0));
        assert_eq!(parse_group_id(file, "dvp"), None);
        assert_eq!(parse_group_id("broken", "dvpn"), None);
    }
}
