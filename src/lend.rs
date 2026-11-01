//! Lending: this machine acting as an exit. `dvpn run --exit` lends on its own;
//! `dvpn connect` requires it (see docs/DESIGN.md §3.9).
//!
//! [`Lending::start`] brings up the exit TUN device and the forwarder, then the system
//! changes an exit needs:
//! - IPv4 forwarding, and an nftables table that NATs the client pool out of the WAN
//!   interface and keeps clients away from private ranges, SMTP and this host;
//! - policy routing that sends lent traffic, and replies from the node's listen ports,
//!   via the original default route. So when this machine is also connected, lending
//!   never goes through its own tunnel and keeps working while that tunnel is down.
//!
//! Dropping [`Lending`] undoes all of it, in reverse order.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::circuit::{ExitSession, IpPool, MTU};
use crate::device::TunDevice;
use crate::exit::{self, EXIT_TUN_ADDR, EXIT_TUN_PREFIX, ExitOptions};
use crate::node::{NatState, NodeStatus};
use crate::policy::ExitPolicy;
use crate::system;

pub const EXIT_TUN: &str = "dvpn-exit";
const POOL: &str = "10.77.0.0/16";
const NFT_TABLE: &str = "dvpn";
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
/// Routing table holding the original default route, for traffic that must bypass our tunnel.
const BYPASS_TABLE: &str = "7700";
/// Rule priorities: first the main table without its default-ish routes (so local and
/// LAN routes still apply), then the bypass table. Both come before the main table.
const PREF_MAIN_SUPPRESSED: &str = "7700";
const PREF_BYPASS: &str = "7701";

/// Shown before lending is enabled for the first time. Calm, but every sentence must
/// stay true for the actual exit policy (docs/DESIGN.md §3.6).
pub const LENDING_WARNING: &str = "\
While you use dvpn, other users' traffic leaves the internet through your connection,
just as yours leaves through theirs. dvpn prefers dedicated exits and only sends
others through you when none of those suits them.

Your exit never lets anyone reach your home network or this computer, and it blocks
direct connections to mail servers, the usual route for spam. dvpn keeps no logs of
what passes through.

If someone misuses your connection, complaints may reach you first, because it's your
IP address. Some internet providers' terms don't allow sharing your connection.";
const CONSENT_FILE: &str = "exit-risk-accepted";

/// Whether the user has accepted [`LENDING_WARNING`] for this data directory.
pub fn consent_given(data_dir: &Path) -> bool {
    data_dir.join(CONSENT_FILE).exists()
}

pub fn record_consent(data_dir: &Path) -> anyhow::Result<()> {
    Ok(crate::identity::write_private(&data_dir.join(CONSENT_FILE), b"accepted\n")?)
}

pub struct LendOptions {
    /// Internet-facing interface; `None` uses the default route's device.
    pub wan: Option<String>,
    /// Destinations refused on top of the default policy and this host's own networks.
    pub extra_deny: Vec<Ipv4Net>,
    pub blocked_tcp_ports: Vec<u16>,
    /// Per session and direction; 0 = unlimited.
    pub rate_mbps: u64,
    pub max_sessions: usize,
    /// The node's listen addresses; replies from their ports bypass our own tunnel.
    pub listen: Vec<Multiaddr>,
}

/// What other parts of the program need to know about lending, cheaply cloneable.
#[derive(Clone)]
pub struct LendingHandle {
    /// Active exit sessions.
    pub active: Arc<AtomicUsize>,
    pub max_sessions: usize,
    /// False once the forwarder has stopped.
    pub alive: Arc<AtomicBool>,
    /// The exit's address pool, so our own tunnel address is never leased locally.
    pub pool: IpPool,
    pub wan: String,
    pub rate_mbps: u64,
}

impl LendingHandle {
    pub fn ready(&self, status: &NodeStatus) -> bool {
        lending_ready(status, self.alive.load(Ordering::Relaxed))
    }
}

/// Lending is ready when others can actually use our exit: the forwarder runs, the exit
/// record is published, and we're reachable directly or through a relay reservation.
pub fn lending_ready(status: &NodeStatus, forwarder_alive: bool) -> bool {
    let reachable = status.publicly_reachable || status.nat == NatState::Public || status.relay_reservations > 0;
    forwarder_alive && status.exit_published && reachable
}

pub struct Lending {
    handle: LendingHandle,
    forwarder: JoinHandle<()>,
    _system: SystemGuard,
}

impl Lending {
    /// Starts lending. `sessions` and `pool` come from a node spawned with an exit config.
    pub fn start(sessions: mpsc::Receiver<ExitSession>, pool: IpPool, options: LendOptions) -> anyhow::Result<Self> {
        // Checked before anything changes on the system.
        let original_default = system::default_route()?.context("no default route; lending needs an internet connection")?;
        let wan = options.wan.clone().unwrap_or_else(|| original_default.dev.clone());
        if !valid_interface_name(&wan) {
            bail!("invalid WAN interface name {wan:?}");
        }
        let device = Arc::new(
            TunDevice::create(EXIT_TUN, EXIT_TUN_ADDR, EXIT_TUN_PREFIX, MTU).context("creating the exit TUN device")?,
        );

        // Never let clients reach this host or the networks it's attached to.
        let mut deny = system::local_ipv4_networks()?;
        deny.extend(options.extra_deny);
        let exit_options = Arc::new(ExitOptions {
            policy: ExitPolicy::new(deny, options.blocked_tcp_ports),
            rate_mbps: options.rate_mbps,
        });

        let mut guard = SystemGuard::default();
        guard.firewall(&wan)?;
        guard.bypass_routes(&original_default, &listen_ports(&options.listen))?;

        let active = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let forwarder = tokio::spawn({
            let (active, alive) = (active.clone(), alive.clone());
            async move {
                exit::forward(device, sessions, exit_options, active).await;
                alive.store(false, Ordering::Relaxed);
                warn!("exit forwarder stopped; lending is down");
            }
        });
        info!(wan = %wan, "lending: exit enabled on {EXIT_TUN} ({EXIT_TUN_ADDR}/{EXIT_TUN_PREFIX})");
        Ok(Self {
            handle: LendingHandle {
                active,
                max_sessions: options.max_sessions,
                alive,
                pool,
                wan,
                rate_mbps: options.rate_mbps,
            },
            forwarder,
            _system: guard,
        })
    }

    pub fn handle(&self) -> LendingHandle {
        self.handle.clone()
    }
}

impl Drop for Lending {
    fn drop(&mut self) {
        // Stop forwarding before the firewall and routes go away.
        self.forwarder.abort();
    }
}

/// System changes made for lending, undone in reverse order on drop.
#[derive(Default)]
struct SystemGuard {
    undo: Vec<Box<dyn FnOnce() -> anyhow::Result<()> + Send>>,
}

impl SystemGuard {
    fn firewall(&mut self, wan: &str) -> anyhow::Result<()> {
        recover_stale_state()?;

        // The original value is kept in /run until we restore it, so it survives a crash
        // (and the next run restores it, not the 1 we set).
        let saved = forward_state_file()?;
        let previous = match std::fs::read_to_string(&saved) {
            Ok(value) => value,
            Err(_) => {
                let value = std::fs::read_to_string(IP_FORWARD).context("reading ip_forward")?;
                std::fs::write(&saved, &value).context("saving the ip_forward setting")?;
                value
            }
        };
        std::fs::write(IP_FORWARD, "1").context("enabling IPv4 forwarding")?;
        self.undo.push(Box::new(move || {
            std::fs::write(IP_FORWARD, previous.trim())?;
            Ok(std::fs::remove_file(&saved)?)
        }));

        system::run_with_stdin("nft", &["-f", "-"], Some(&nft_ruleset(wan)))?;
        self.undo.push(Box::new(|| system::run("nft", &["delete", "table", "ip", NFT_TABLE]).map(drop)));
        Ok(())
    }

    fn bypass_routes(&mut self, original_default: &system::NextHop, ports: &[(&'static str, u16)]) -> anyhow::Result<()> {
        let mut add = vec!["-4", "route", "replace", "default"];
        let hop = original_default.args();
        add.extend(hop.iter().map(String::as_str));
        add.extend(["table", BYPASS_TABLE]);
        system::run("ip", &add)?;
        self.undo.push(Box::new(|| system::run("ip", &["-4", "route", "flush", "table", BYPASS_TABLE]).map(drop)));

        let mut selectors: Vec<Vec<String>> = vec![vec!["iif".into(), EXIT_TUN.into()]];
        for (protocol, port) in ports {
            selectors.push(vec!["ipproto".into(), protocol.to_string(), "sport".into(), port.to_string()]);
        }
        for selector in selectors {
            for action in [
                ["lookup", "main", "suppress_prefixlength", "1", "pref", PREF_MAIN_SUPPRESSED].as_slice(),
                ["lookup", BYPASS_TABLE, "pref", PREF_BYPASS].as_slice(),
            ] {
                let mut rule: Vec<String> = ["-4", "rule", "add"].map(String::from).to_vec();
                rule.extend(selector.iter().cloned());
                rule.extend(action.iter().map(|s| s.to_string()));
                system::run("ip", &rule.iter().map(String::as_str).collect::<Vec<_>>())?;
                rule[2] = "del".into();
                self.undo.push(Box::new(move || {
                    system::run("ip", &rule.iter().map(String::as_str).collect::<Vec<_>>()).map(drop)
                }));
            }
        }
        Ok(())
    }
}

impl Drop for SystemGuard {
    fn drop(&mut self) {
        for undo in self.undo.drain(..).rev() {
            if let Err(e) = undo() {
                warn!("lending cleanup step failed: {e:#}");
            }
        }
        if !std::thread::panicking() {
            info!("lending stopped; firewall and routing restored");
        }
    }
}

/// Removes the firewall table and policy-routing rules a previous dvpn left behind when
/// it couldn't clean up (killed with SIGKILL, crashed, power loss). Refuses instead if
/// another dvpn runs in this network namespace, since they may be its.
fn recover_stale_state() -> anyhow::Result<()> {
    let table = system::run("nft", &["list", "table", "ip", NFT_TABLE]).is_ok();
    let rules = system::run("ip", &["-4", "rule", "show"]).is_ok_and(|out| {
        out.lines()
            .any(|l| l.starts_with(&format!("{PREF_MAIN_SUPPRESSED}:")) || l.starts_with(&format!("{PREF_BYPASS}:")))
    });
    if !table && !rules {
        return Ok(());
    }
    if other_dvpn_in_this_namespace() {
        bail!(
            "another dvpn is already lending on this machine (nftables table `ip {NFT_TABLE}` exists); \
             stop it first, or if none is running, remove the leftovers with `sudo scripts/exit-teardown.sh`"
        );
    }
    if table {
        system::run("nft", &["delete", "table", "ip", NFT_TABLE])?;
    }
    for pref in [PREF_MAIN_SUPPRESSED, PREF_BYPASS] {
        while system::run("ip", &["-4", "rule", "del", "pref", pref]).is_ok() {}
    }
    let _ = system::run("ip", &["-4", "route", "flush", "table", BYPASS_TABLE]);
    warn!("removed firewall and routing rules left behind by a dvpn that didn't shut down cleanly");
    Ok(())
}

/// Whether another process named `dvpn` shares our network namespace (needs root to
/// read other processes' namespaces, which lending has).
fn other_dvpn_in_this_namespace() -> bool {
    let ours = std::fs::read_link("/proc/self/ns/net").ok();
    let me = std::process::id().to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        pid.chars().all(|c| c.is_ascii_digit())
            && pid != me
            && std::fs::read_to_string(entry.path().join("comm")).is_ok_and(|c| c.trim() == "dvpn")
            && std::fs::read_link(entry.path().join("ns/net")).ok() == ours
    })
}

/// `/run/dvpn-ip-forward-<netns>`: per network namespace, since each has its own
/// ip_forward (the netns test harness runs several exits on one host).
fn forward_state_file() -> anyhow::Result<std::path::PathBuf> {
    let ns = std::fs::read_link("/proc/self/ns/net").context("reading the network namespace")?;
    let id: String = ns.to_string_lossy().chars().filter(char::is_ascii_digit).collect();
    Ok(std::path::PathBuf::from(format!("/run/dvpn-ip-forward-{id}")))
}

/// The nftables table an exit needs; the same rules as scripts/exit-setup.sh.
pub fn nft_ruleset(wan: &str) -> String {
    format!(
        r#"table ip {NFT_TABLE} {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {POOL} oifname "{wan}" masquerade
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "{EXIT_TUN}" oifname != "{wan}" drop
        iifname "{EXIT_TUN}" ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} drop
        iifname "{EXIT_TUN}" tcp dport 25 drop
        oifname "{EXIT_TUN}" ct state established,related accept
        oifname "{EXIT_TUN}" drop
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "{EXIT_TUN}" drop
    }}
}}
"#
    )
}

/// TCP and UDP ports the node listens on.
pub fn listen_ports(listen: &[Multiaddr]) -> Vec<(&'static str, u16)> {
    let mut ports = Vec::new();
    for addr in listen {
        let port = addr.iter().find_map(|p| match p {
            Protocol::Tcp(port) => Some(("tcp", port)),
            Protocol::Udp(port) => Some(("udp", port)),
            _ => None,
        });
        if let Some(port) = port
            && port.1 != 0
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    ports
}

/// Linux interface names: at most 15 characters, no quotes or spaces. Checked because
/// the WAN name is written into the nftables ruleset.
pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(nat: NatState, reservations: usize, published: bool, public: bool) -> NodeStatus {
        NodeStatus {
            nat,
            relay_reservations: reservations,
            external_addrs: vec![],
            hole_punches: 0,
            publicly_reachable: public,
            exit_published: published,
        }
    }

    #[test]
    fn lending_is_ready_only_when_usable_by_others() {
        // Reachable directly, through AutoNAT, or through a relay; published; forwarding.
        assert!(lending_ready(&status(NatState::Unknown, 0, true, true), true));
        assert!(lending_ready(&status(NatState::Public, 0, true, false), true));
        assert!(lending_ready(&status(NatState::Private, 1, true, false), true));

        assert!(!lending_ready(&status(NatState::Public, 0, false, true), true), "record not published");
        assert!(!lending_ready(&status(NatState::Public, 0, true, true), false), "forwarder stopped");
        assert!(!lending_ready(&status(NatState::Private, 0, true, false), true), "unreachable behind NAT");
        assert!(!lending_ready(&status(NatState::Unknown, 0, true, false), true), "reachability unknown");
    }

    #[test]
    fn ruleset_nats_the_pool_out_of_the_wan_and_confines_clients() {
        let rules = nft_ruleset("eth0");
        assert!(rules.contains(r#"ip saddr 10.77.0.0/16 oifname "eth0" masquerade"#));
        assert!(rules.contains(r#"iifname "dvpn-exit" oifname != "eth0" drop"#));
        assert!(rules.contains(r#"iifname "dvpn-exit" tcp dport 25 drop"#));
        assert!(rules.contains("192.168.0.0/16"));
        // Nothing may start a connection towards clients through the exit.
        assert!(rules.contains(r#"oifname "dvpn-exit" ct state established,related accept"#));
        assert!(rules.contains(r#"oifname "dvpn-exit" drop"#));
        // The input chain keeps clients away from services on this host.
        assert!(rules.contains("chain input {\n        type filter hook input priority filter; policy accept;\n        iifname \"dvpn-exit\" drop"));
    }

    #[test]
    fn finds_listen_ports() {
        let listen: Vec<Multiaddr> = ["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic-v1", "/ip6/::/tcp/4001", "/ip4/0.0.0.0/tcp/0"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(listen_ports(&listen), [("tcp", 4001), ("udp", 4001)]);
    }

    #[test]
    fn interface_names_are_checked() {
        assert!(valid_interface_name("eth0"));
        assert!(valid_interface_name("wlp2s0"));
        assert!(!valid_interface_name(""));
        assert!(!valid_interface_name("eth0\" drop; #"));
        assert!(!valid_interface_name("averyveryverylongname"));
    }
}
