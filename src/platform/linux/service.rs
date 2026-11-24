//! Running as a system service: systemd socket activation, shutdown signals, and who
//! may control the service. Anyone can open the socket, but the service answers only
//! users [`Access`] allows: root, people signed in at this computer (polkit action
//! [`POLKIT_ACTION`]), and members of the [`SERVICE_GROUP`] group. Group membership is
//! read from `/etc/group` when connecting, so it applies at once, without logging out.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context;
use tracing::info;

use super::ipc::{self, Listener, Peer};

pub const SERVICE_SOCKET: &str = "/run/dvpn/control.sock";
pub const SERVICE_DATA_DIR: &str = "/var/lib/dvpn";
pub const SERVICE_GROUP: &str = "dvpn";
/// The polkit action that lets a user control the service (`packaging/dev.dvpn.policy`):
/// allowed without a password for whoever is signed in at this computer.
pub const POLKIT_ACTION: &str = "dev.dvpn.control";
const PKCHECK: &str = "/usr/bin/pkcheck";
/// How long a polkit answer is reused for the same process (the app reconnects often).
const AUTH_CACHE: Duration = Duration::from_secs(300);
/// First file descriptor passed by systemd socket activation.
const SD_LISTEN_FDS_START: i32 = 3;

/// Completes on SIGINT, SIGTERM or SIGHUP (e.g. the terminal window closing), so every
/// command can undo its routes and firewall rules instead of being killed mid-way.
/// The handlers are installed when this is called, not when it's first polled.
pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    })
}

/// The socket systemd passed (socket activation), or a new one bound at `path` with
/// mode 0666: anyone may connect, and [`Access`] decides whom the service answers.
pub async fn listen(path: &Path) -> anyhow::Result<Listener> {
    if let Some(listener) = systemd_listener()? {
        return Ok(listener);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    ipc::bind_public(path).await
}

/// Who may control the service; see the module docs.
#[derive(Default)]
pub struct Access {
    /// Processes polkit allowed, by (uid, pid, start time), and when.
    allowed: Mutex<HashMap<(u32, i32, u64), Instant>>,
}

impl Access {
    pub fn check(&self, peer: Option<Peer>) -> Result<(), String> {
        let peer = peer.ok_or_else(permission_help)?;
        let uid = peer.uid;
        if uid == 0 || Some(uid) == own_uid() || in_service_group(uid) {
            return Ok(());
        }
        let Some(pid) = peer.pid else {
            return Err(permission_help());
        };
        let Some(start) = process_start_time(pid) else {
            return Err(permission_help());
        };
        let key = (uid, pid, start);
        let mut allowed = self.allowed.lock().expect("access lock");
        allowed.retain(|_, at| at.elapsed() < AUTH_CACHE);
        if allowed.contains_key(&key) {
            return Ok(());
        }
        drop(allowed);
        if polkit_allows(pid, start, uid) {
            self.allowed.lock().expect("access lock").insert(key, Instant::now());
            return Ok(());
        }
        Err(permission_help())
    }
}

fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Membership as configured now, not as the user's processes got it at login: adding
/// someone to the group works without them logging out and back in.
fn in_service_group(uid: u32) -> bool {
    let (Ok(passwd), Ok(group)) = (std::fs::read_to_string("/etc/passwd"), std::fs::read_to_string("/etc/group")) else {
        return false;
    };
    is_group_member(&passwd, &group, uid, SERVICE_GROUP)
}

fn is_group_member(passwd: &str, group: &str, uid: u32, group_name: &str) -> bool {
    let Some(gid) = parse_group_id(group, group_name) else {
        return false;
    };
    let user = passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 4 && fields[2].parse() == Ok(uid)).then(|| (fields[0].to_string(), fields[3].parse::<u32>().ok()))
    });
    let Some((name, primary_gid)) = user else {
        return false;
    };
    let members = group.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 4 && fields[0] == group_name).then(|| fields[3].to_string())
    });
    primary_gid == Some(gid) || members.is_some_and(|m| m.split(',').any(|member| member.trim() == name))
}

/// A process's start time (field 22 of `/proc/<pid>/stat`), which polkit uses with the
/// pid so a reused pid can't inherit another process's permission.
fn process_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name (field 2) is in parentheses and may contain spaces.
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Asks polkit whether the process may control dvpn, without prompting for a password.
fn polkit_allows(pid: i32, start: u64, uid: u32) -> bool {
    if !Path::new(PKCHECK).exists() {
        return false;
    }
    Command::new(PKCHECK)
        .args(["--action-id", POLKIT_ACTION, "--process", &format!("{pid},{start},{uid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Takes the first socket passed with `LISTEN_FDS`, if it was passed to this process.
fn systemd_listener() -> anyhow::Result<Option<Listener>> {
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
    Ok(Some(Listener::from_std(listener)?))
}

fn parse_group_id(group_file: &str, name: &str) -> Option<u32> {
    group_file.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

pub fn permission_help() -> String {
    format!(
        "This account isn't allowed to control dvpn. Anyone signed in at this computer \
         can use it; for other accounts (e.g. over SSH), an administrator can allow it with:\n\n    \
         sudo usermod -aG {SERVICE_GROUP} <user>\n\n\
         This applies right away; there's no need to log out."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_membership_is_read_from_the_files() {
        let passwd = "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:998::/home/bob:/bin/sh\ncarol:x:1002:1002::/home/c:/bin/sh\n";
        let group = "dvpn:x:998:alice,dave\nalice:x:1000:\n";
        assert!(is_group_member(passwd, group, 1000, "dvpn"), "listed member");
        assert!(is_group_member(passwd, group, 1001, "dvpn"), "primary group");
        assert!(!is_group_member(passwd, group, 1002, "dvpn"));
        assert!(!is_group_member(passwd, group, 4242, "dvpn"), "unknown user");
        assert!(!is_group_member(passwd, "other:x:5:carol\n", 1002, "dvpn"), "no such group");
    }

    #[test]
    fn reads_process_start_times() {
        let stat = "4242 (my app (x)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 200";
        assert_eq!(parse_start_time(stat), Some(987654));
        assert!(process_start_time(std::process::id() as i32).is_some());
    }

    #[test]
    fn the_services_own_user_is_allowed() {
        // Tests and a service started by hand run as the socket's peer themselves.
        assert!(own_uid().is_some());
    }

    #[test]
    fn finds_group_ids() {
        let file = "root:x:0:\nsudo:x:27:alice\ndvpn:x:998:alice,bob\ndvpnx:x:5:\n";
        assert_eq!(parse_group_id(file, "dvpn"), Some(998));
        assert_eq!(parse_group_id(file, "root"), Some(0));
        assert_eq!(parse_group_id(file, "dvp"), None);
        assert_eq!(parse_group_id("broken", "dvpn"), None);
    }
}
