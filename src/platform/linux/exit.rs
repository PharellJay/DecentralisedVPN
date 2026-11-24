//! What an exit needs from the system: IPv4 forwarding, an nftables table that NATs the
//! client pool out of the WAN interface and keeps clients away from private ranges,
//! this host and ports the policy refuses, and policy routing for lent traffic.

use std::net::Ipv4Addr;

use anyhow::{Context, bail};
use tracing::{info, warn};

use super::cmd;
use super::net::NextHop;
use crate::lend::{EXIT_TUN, POOL};
use crate::policy::Ports;

const NFT_TABLE: &str = "dvpn";
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
/// Routing table holding the original default route, for traffic that must bypass our tunnel.
const BYPASS_TABLE: &str = "7700";
/// Rule priorities: first the main table without its default-ish routes (so local and
/// LAN routes still apply), then the bypass table. Both come before the main table.
const PREF_MAIN_SUPPRESSED: &str = "7700";
const PREF_BYPASS: &str = "7701";

/// Refuses `ip` as a destination for lent traffic, in the running firewall.
pub fn deny_destination(ip: Ipv4Addr) -> anyhow::Result<()> {
    let element = format!("{{ {ip} }}");
    cmd::run("nft", &["add", "element", "ip", NFT_TABLE, "self_deny", &element]).map(drop)
}

/// System changes made for lending, undone in reverse order on drop.
#[derive(Default)]
pub struct ExitNetwork {
    undo: Vec<Box<dyn FnOnce() -> anyhow::Result<()> + Send + Sync>>,
}

impl ExitNetwork {
    /// Forwarding, NAT and the firewall for lent traffic leaving through `wan`, and
    /// routing that sends lent traffic and replies from `listen_ports` via
    /// `original_default`: so when this machine is also connected, lending never goes
    /// through its own tunnel and keeps working while that tunnel is down.
    pub fn install(
        wan: &str,
        ports: &Ports,
        original_default: &NextHop,
        listen_ports: &[(&'static str, u16)],
    ) -> anyhow::Result<Self> {
        let mut network = Self::default();
        network.firewall(wan, ports)?;
        network.bypass_routes(original_default, listen_ports)?;
        Ok(network)
    }

    fn firewall(&mut self, wan: &str, ports: &Ports) -> anyhow::Result<()> {
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
        // Forwarding is a host-wide switch. If it was off, this host routed for nobody, so
        // the firewall keeps it that way for everything but lent traffic; otherwise
        // whatever needed it (containers, another VPN) keeps working.
        let forwarding_was_off = previous.trim() == "0";
        std::fs::write(IP_FORWARD, "1").context("enabling IPv4 forwarding")?;
        self.undo.push(Box::new(move || {
            std::fs::write(IP_FORWARD, previous.trim())?;
            Ok(std::fs::remove_file(&saved)?)
        }));

        cmd::run_with_stdin("nft", &["-f", "-"], Some(&nft_ruleset(wan, ports, forwarding_was_off)))?;
        self.undo.push(Box::new(|| cmd::run("nft", &["delete", "table", "ip", NFT_TABLE]).map(drop)));
        Ok(())
    }

    fn bypass_routes(&mut self, original_default: &NextHop, ports: &[(&'static str, u16)]) -> anyhow::Result<()> {
        let mut add = vec!["-4", "route", "replace", "default"];
        let hop = original_default.args();
        add.extend(hop.iter().map(String::as_str));
        add.extend(["table", BYPASS_TABLE]);
        cmd::run("ip", &add)?;
        self.undo.push(Box::new(|| cmd::run("ip", &["-4", "route", "flush", "table", BYPASS_TABLE]).map(drop)));

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
                cmd::run("ip", &rule.iter().map(String::as_str).collect::<Vec<_>>())?;
                rule[2] = "del".into();
                self.undo.push(Box::new(move || {
                    cmd::run("ip", &rule.iter().map(String::as_str).collect::<Vec<_>>()).map(drop)
                }));
            }
        }
        Ok(())
    }
}

impl Drop for ExitNetwork {
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
pub fn recover_stale_state() -> anyhow::Result<()> {
    let table = cmd::run("nft", &["list", "table", "ip", NFT_TABLE]).is_ok();
    let rules = cmd::run("ip", &["-4", "rule", "show"]).is_ok_and(|out| {
        out.lines()
            .any(|l| l.starts_with(&format!("{PREF_MAIN_SUPPRESSED}:")) || l.starts_with(&format!("{PREF_BYPASS}:")))
    });
    if !table && !rules {
        return Ok(());
    }
    if super::other_dvpn_in_this_namespace() {
        bail!(
            "another dvpn is already lending on this machine (nftables table `ip {NFT_TABLE}` exists); \
             stop it first, or if none is running, remove the leftovers with `sudo scripts/exit-teardown.sh`"
        );
    }
    if table {
        cmd::run("nft", &["delete", "table", "ip", NFT_TABLE])?;
    }
    for pref in [PREF_MAIN_SUPPRESSED, PREF_BYPASS] {
        while cmd::run("ip", &["-4", "rule", "del", "pref", pref]).is_ok() {}
    }
    let _ = cmd::run("ip", &["-4", "route", "flush", "table", BYPASS_TABLE]);
    warn!("removed firewall and routing rules left behind by a dvpn that didn't shut down cleanly");
    Ok(())
}

/// `dvpn-ip-forward-<netns>` in the service's runtime directory (`$RUNTIME_DIRECTORY`,
/// set by systemd), else in `/run`: per network namespace, since each has its own
/// ip_forward (the netns test harness runs several exits on one host).
fn forward_state_file() -> anyhow::Result<std::path::PathBuf> {
    let ns = std::fs::read_link("/proc/self/ns/net").context("reading the network namespace")?;
    let id: String = ns.to_string_lossy().chars().filter(char::is_ascii_digit).collect();
    let dir = std::env::var_os("RUNTIME_DIRECTORY")
        .map(std::path::PathBuf::from)
        .filter(|d| d.is_absolute())
        .unwrap_or_else(|| "/run".into());
    Ok(dir.join(format!("dvpn-ip-forward-{id}")))
}

/// The nftables table an exit needs; for a dedicated exit, the same rules as
/// scripts/exit-setup.sh. `ports` repeats the port policy (see [`Ports`]). With
/// `only_lent_forwarding`, nothing but lent traffic is forwarded (IPv4 forwarding was
/// off before lending turned it on).
pub fn nft_ruleset(wan: &str, ports: &Ports, only_lent_forwarding: bool) -> String {
    let special = crate::addrs::SPECIAL_PURPOSE_V4.join(", ");
    let ports = ports.nft_rules(EXIT_TUN);
    let others = if only_lent_forwarding {
        format!("\n        iifname != \"{EXIT_TUN}\" drop")
    } else {
        String::new()
    };
    format!(
        r#"table ip {NFT_TABLE} {{
    set self_deny {{
        type ipv4_addr
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {POOL} oifname "{wan}" masquerade
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "{EXIT_TUN}" oifname != "{wan}" drop
        iifname "{EXIT_TUN}" ip daddr {{ {special} }} drop
        iifname "{EXIT_TUN}" ip daddr @self_deny drop{ports}
        oifname "{EXIT_TUN}" ct state established,related accept
        oifname "{EXIT_TUN}" drop{others}
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "{EXIT_TUN}" drop
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_nats_the_pool_out_of_the_wan_and_confines_clients() {
        let rules = nft_ruleset("eth0", &Ports::AllExcept(vec![25]), false);
        assert!(rules.contains(r#"ip saddr 10.77.0.0/16 oifname "eth0" masquerade"#));
        assert!(rules.contains(r#"iifname "dvpn-exit" oifname != "eth0" drop"#));
        assert!(rules.contains(r#"iifname "dvpn-exit" tcp dport { 25 } drop"#));
        assert!(rules.contains("192.168.0.0/16"));
        // Nothing may start a connection towards clients through the exit.
        assert!(rules.contains(r#"oifname "dvpn-exit" ct state established,related accept"#));
        assert!(rules.contains(r#"oifname "dvpn-exit" drop"#));
        // The input chain keeps clients away from services on this host.
        assert!(rules.contains("chain input {\n        type filter hook input priority filter; policy accept;\n        iifname \"dvpn-exit\" drop"));
        // The firewall refuses every range the userspace policy refuses, and our own address.
        for net in crate::addrs::SPECIAL_PURPOSE_V4 {
            assert!(rules.contains(net), "{net} missing from the firewall");
        }
        assert!(rules.contains("ip daddr @self_deny drop"));
        assert!(!rules.contains(r#"iifname != "dvpn-exit" drop"#), "forwarding was already on: leave others alone");
    }

    #[test]
    fn ruleset_forwards_only_lent_traffic_if_forwarding_was_off() {
        let rules = nft_ruleset("eth0", &Ports::Reduced, true);
        assert!(rules.contains(r#"iifname "dvpn-exit" udp dport != {"#), "users' exits forward common ports only");
        let others = rules.find(r#"iifname != "dvpn-exit" drop"#).expect("other forwarding is dropped");
        assert!(rules.find(r#"oifname "dvpn-exit" ct state established,related accept"#).unwrap() < others, "replies to clients still pass");
    }

    #[test]
    fn rulesets_parse() {
        for ports in [Ports::AllExcept(vec![25, 465]), Ports::Reduced] {
            for only_lent in [false, true] {
                crate::platform::linux::assert_nft_parses(&nft_ruleset("eth0", &ports, only_lent));
            }
        }
    }
}
