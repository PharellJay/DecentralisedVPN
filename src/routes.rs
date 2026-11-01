//! Client routing while connected: all IPv4 through the TUN device, the entry relay(s)
//! via the original route, IPv6 blackholed, DNS pinned to the tunnel, and a firewall
//! that lets nothing *start* a connection to this machine through the tunnel (the exit
//! is untrusted and could otherwise reach local services).
//!
//! Everything is undone when the [`RouteGuard`] drops. While it exists the routes stay
//! in place even if the circuit fails, so traffic is dropped rather than leaked
//! (kill switch).

use std::collections::HashSet;
use std::net::Ipv4Addr;

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::system::{self, NextHop};

/// Together these override the default route without replacing it.
const CAPTURE_ROUTES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const NFT_TABLE: &str = "dvpn-client";
/// systemd-resolved's stub resolvers; only these honour the per-link DNS we set.
const RESOLVED_STUBS: [&str; 2] = ["127.0.0.53", "127.0.0.54"];

pub struct RouteGuard {
    dev: String,
    /// The pre-VPN default route, used for relay exemptions.
    original_default: Option<NextHop>,
    exempted: HashSet<Ipv4Addr>,
    /// Commands that undo what we installed, applied in reverse order.
    undo: Vec<(&'static str, Vec<String>)>,
    /// Problems that weaken protection without stopping it, for the user to see.
    pub warnings: Vec<String>,
}

impl RouteGuard {
    /// Routes all IPv4 traffic into `dev` and blackholes IPv6. With `dns`, the
    /// tunnel's DNS server is set via systemd-resolved.
    pub fn install(dev: &str, dns: Option<Ipv4Addr>) -> anyhow::Result<Self> {
        if !crate::lend::valid_interface_name(dev) {
            bail!("invalid TUN device name {dev:?}");
        }
        let mut guard = Self {
            dev: dev.to_string(),
            original_default: system::default_route()?,
            exempted: HashSet::new(),
            undo: Vec::new(),
            warnings: Vec::new(),
        };
        // Fails closed: without the inbound firewall we don't connect at all.
        if system::run("nft", &["list", "table", "ip", NFT_TABLE]).is_ok() {
            // Left over from a run that couldn't clean up; this device name is ours.
            system::run("nft", &["delete", "table", "ip", NFT_TABLE])?;
        }
        system::run_with_stdin("nft", &["-f", "-"], Some(&inbound_ruleset(dev))).context("installing the inbound firewall")?;
        guard.undo.push(("nft", ["delete", "table", "ip", NFT_TABLE].map(String::from).to_vec()));

        for half in CAPTURE_ROUTES {
            guard.apply("ip", &["-4", "route", "add", half, "dev", dev], &["-4", "route", "del", half, "dev", dev])?;
        }
        let has_ipv6 = system::run("ip", &["-6", "route", "show", "default"]).is_ok_and(|out| !out.trim().is_empty());
        for half in ["::/1", "8000::/1"] {
            if let Err(e) = guard.apply(
                "ip",
                &["-6", "route", "add", "blackhole", half],
                &["-6", "route", "del", "blackhole", half],
            ) {
                // With IPv6 connectivity this would be a leak, so refuse; without it, nothing can leak.
                if has_ipv6 {
                    return Err(e).context("could not block IPv6, which would bypass the tunnel");
                }
                warn!("could not block IPv6 ({e:#}); this machine has no IPv6 route, so nothing leaks");
            }
        }
        if let Some(dns) = dns {
            let dns = dns.to_string();
            let configured = system::run("resolvectl", &["dns", dev, &dns])
                .and_then(|_| system::run("resolvectl", &["domain", dev, "~."]));
            match configured {
                Ok(_) => {
                    guard.undo.push(("resolvectl", vec!["revert".into(), dev.into()]));
                    let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
                    if uses_resolved_stub(&resolv_conf) {
                        info!("DNS goes through the tunnel");
                    } else {
                        guard.warn(
                            "/etc/resolv.conf doesn't use systemd-resolved, so DNS queries may go to your \
                             local resolver outside the tunnel; point it at 127.0.0.53 or set DNS yourself",
                        );
                    }
                }
                Err(e) => guard.warn(&format!("could not configure DNS ({e:#}); DNS queries may leak outside the tunnel")),
            }
        }
        Ok(guard)
    }

    fn warn(&mut self, message: &str) {
        warn!("{message}");
        self.warnings.push(message.to_string());
    }

    /// Re-adds the routes that capture all IPv4 traffic, in case the kernel or another
    /// program removed them (Linux drops a device's routes when it loses its last
    /// IPv4 address). Idempotent.
    pub fn reassert(&self) -> anyhow::Result<()> {
        for half in CAPTURE_ROUTES {
            system::run("ip", &["-4", "route", "replace", half, "dev", &self.dev])?;
        }
        Ok(())
    }

    /// Keeps `ip` (an entry relay) on its original route, so the tunnel's own
    /// traffic doesn't loop into the tunnel.
    pub fn exempt(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        if !self.exempted.insert(ip) {
            return Ok(());
        }
        let current = system::route_get(ip)?;
        let hop = match current {
            Some(hop) if hop.dev != self.dev => hop,
            _ => self
                .original_default
                .clone()
                .context("no original route to the entry relay")?,
        };
        if hop.dev == "lo" {
            bail!("entry relay {ip} is this machine");
        }
        let target = format!("{ip}/32");
        let mut add = vec!["-4".to_string(), "route".into(), "replace".into(), target.clone()];
        add.extend(hop.args());
        let add: Vec<&str> = add.iter().map(String::as_str).collect();
        self.apply("ip", &add, &["-4", "route", "del", &target])
    }

    fn apply(&mut self, program: &'static str, args: &[&str], undo: &[&str]) -> anyhow::Result<()> {
        system::run(program, args)?;
        self.undo.push((program, undo.iter().map(|s| s.to_string()).collect()));
        Ok(())
    }
}

/// Drops everything arriving on the tunnel device except replies to connections this
/// machine started.
pub fn inbound_ruleset(dev: &str) -> String {
    format!(
        r#"table ip {NFT_TABLE} {{
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "{dev}" ct state established,related accept
        iifname "{dev}" drop
    }}
}}
"#
    )
}

/// True if every nameserver in `resolv_conf` is systemd-resolved's stub.
pub fn uses_resolved_stub(resolv_conf: &str) -> bool {
    let servers: Vec<&str> = resolv_conf
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .map(str::trim)
        .collect();
    !servers.is_empty() && servers.iter().all(|s| RESOLVED_STUBS.contains(s))
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for (program, args) in self.undo.drain(..).rev() {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(e) = system::run(program, &args) {
                warn!("cleanup step failed: {e:#}");
            }
        }
        info!("routes restored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_firewall_only_lets_replies_in() {
        let rules = inbound_ruleset("dvpn0");
        assert!(rules.contains(r#"iifname "dvpn0" ct state established,related accept"#));
        assert!(rules.contains(r#"iifname "dvpn0" drop"#));
        let accept = rules.find("accept\n        iifname").unwrap();
        assert!(accept < rules.rfind("drop").unwrap(), "replies must be accepted before the drop");
    }

    #[test]
    fn detects_whether_dns_goes_through_systemd_resolved() {
        assert!(uses_resolved_stub("# managed by resolved\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"));
        assert!(uses_resolved_stub("nameserver 127.0.0.54\n"));
        assert!(!uses_resolved_stub("nameserver 192.168.1.1\n"), "the router's resolver bypasses the tunnel");
        assert!(!uses_resolved_stub("nameserver 127.0.0.53\nnameserver 8.8.8.8\n"), "any non-stub server can leak");
        assert!(!uses_resolved_stub(""), "no nameserver: libc falls back to 127.0.0.1, not resolved's stub");
    }
}
