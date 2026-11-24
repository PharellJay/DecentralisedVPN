//! Client protection while connected, in two layers with different lifetimes:
//!
//! - [`KillSwitch`]: a firewall that lets nothing leave this machine except through the
//!   tunnel device, the LAN, and dvpn's own traffic (recognised by its cgroup), plus
//!   IPv6 blackholed. It also lets nothing *start* a connection to this machine through
//!   the tunnel (the exit is untrusted and could otherwise reach local services). It is
//!   installed when the user connects and removed only when they disconnect, so it
//!   holds while (re)connecting and when the client fails: traffic is blocked, never
//!   leaked. Because it filters by interface rather than relying on routes, routes
//!   pushed by a rogue DHCP server or router advertisement (more specific than ours,
//!   "TunnelVision") can't steer traffic around the tunnel either.
//! - [`RouteGuard`]: all IPv4 routed into the TUN device, the entry relay(s) via the
//!   original route, and DNS pinned to the tunnel: set in systemd-resolved, and any
//!   query that would still leave outside the tunnel (a resolver on the LAN, from
//!   `/etc/resolv.conf` or a local forwarder) redirected into it by the firewall. It
//!   lives as long as a client runs.
//!
//! Each undoes what it installed when dropped.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use tracing::{info, warn};

use super::cmd;
use super::net::{self, NextHop};
use crate::dns::DnsOverTls;

/// Together these override the default route without replacing it.
const CAPTURE_ROUTES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const IPV6_BLACKHOLES: [&str; 2] = ["::/1", "8000::/1"];
const NFT_TABLE: &str = "dvpn-client";
/// [`RouteGuard`]'s DNS redirect; separate, since it lives only while a client runs.
const DNS_TABLE: &str = "dvpn-dns";
/// systemd-resolved's stub resolvers; only these honour the per-link DNS we set.
const RESOLVED_STUBS: [&str; 2] = ["127.0.0.53", "127.0.0.54"];
/// Destinations that count as the local network and stay reachable while blocked.
const LAN_V4: [&str; 7] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
];
/// A network this host is attached to counts as LAN only if it's at least this narrow,
/// so a DHCP server can't hand out a huge netmask to declare the internet "local".
const MIN_LAN_PREFIX: u8 = 16;

fn resolvectl_value(dot: DnsOverTls) -> &'static str {
    match dot {
        DnsOverTls::Yes => "yes",
        DnsOverTls::Opportunistic => "opportunistic",
        DnsOverTls::No => "no",
    }
}

/// `<ip>#<name>` for resolvers with a known TLS name, so systemd-resolved checks the
/// server's certificate.
fn dns_server_spec(dns: Ipv4Addr) -> String {
    match crate::dns::tls_name(dns) {
        Some(name) => format!("{dns}#{name}"),
        None => dns.to_string(),
    }
}

/// The firewall that blocks everything but the tunnel; see the module docs.
pub struct KillSwitch {
    dev: String,
    /// Whether outgoing traffic is filtered (the cgroup of dvpn could be identified).
    filters_output: bool,
    blackholes: Vec<&'static str>,
    /// Problems that weaken protection without stopping it, for the user to see.
    pub warnings: Vec<String>,
}

impl KillSwitch {
    /// Installs the firewall for tunnel device `dev`. Fails (and leaves nothing behind)
    /// if even the inbound part can't be installed, or IPv6 can't be blocked on a host
    /// with IPv6 connectivity: connecting then is refused rather than unprotected.
    pub fn install(dev: &str) -> anyhow::Result<Self> {
        if !super::valid_interface_name(dev) {
            bail!("invalid TUN device name {dev:?}");
        }
        let mut switch = Self {
            dev: dev.to_string(),
            filters_output: false,
            blackholes: Vec::new(),
            warnings: Vec::new(),
        };
        delete_tables();
        let cgroup = own_cgroup();
        let lan = lan_networks();
        let full = cgroup.as_ref().map(|(level, path)| ruleset(dev, Some((*level, path)), &lan));
        match full.map(|rules| cmd::run_with_stdin("nft", &["-f", "-"], Some(&rules))) {
            Some(Ok(_)) => switch.filters_output = true,
            failed => {
                let reason = match failed {
                    Some(Err(e)) => format!("{e:#}"),
                    _ => "dvpn's own traffic can't be told apart (no cgroup v2)".into(),
                };
                delete_tables();
                cmd::run_with_stdin("nft", &["-f", "-"], Some(&ruleset(dev, None, &lan)))
                    .context("installing the firewall")?;
                switch.warn(&format!(
                    "the firewall can't block traffic that bypasses the tunnel ({reason}); protection relies on routes only"
                ));
            }
        }

        let has_ipv6 = cmd::run("ip", &["-6", "route", "show", "default"]).is_ok_and(|out| !out.trim().is_empty());
        for half in IPV6_BLACKHOLES {
            // `replace`, so a blackhole left by a crashed run doesn't make this fail.
            match cmd::run("ip", &["-6", "route", "replace", "blackhole", half]) {
                Ok(_) => switch.blackholes.push(half),
                // With IPv6 connectivity this would be a leak, so refuse; without it, nothing can leak.
                Err(e) if has_ipv6 && !switch.filters_output => {
                    return Err(e).context("could not block IPv6, which would bypass the tunnel");
                }
                Err(e) => warn!("could not blackhole IPv6 ({e:#}); the firewall still blocks it"),
            }
        }
        info!("kill switch on: nothing leaves this machine except through the tunnel");
        Ok(switch)
    }

    /// Whether outgoing traffic outside the tunnel is blocked by the firewall (and not
    /// only by routes).
    pub fn filters_output(&self) -> bool {
        self.filters_output
    }

    /// Rebuilds the set of local networks, after this machine changed networks.
    pub fn refresh_lan(&self) {
        if !self.filters_output {
            return;
        }
        let elements = lan_networks().iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
        let script = format!("flush set ip {NFT_TABLE} lan\nadd element ip {NFT_TABLE} lan {{ {elements} }}\n");
        if let Err(e) = cmd::run_with_stdin("nft", &["-f", "-"], Some(&script)) {
            warn!("could not update the local networks in the firewall: {e:#}");
        }
    }

    fn warn(&mut self, message: &str) {
        warn!("{message}");
        self.warnings.push(message.to_string());
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        for half in self.blackholes.drain(..) {
            if let Err(e) = cmd::run("ip", &["-6", "route", "del", "blackhole", half]) {
                warn!("cleanup step failed: {e:#}");
            }
        }
        delete_tables();
        info!("kill switch off ({})", self.dev);
    }
}

fn delete_tables() {
    for family in ["ip", "ip6"] {
        if cmd::run("nft", &["list", "table", family, NFT_TABLE]).is_ok() {
            let _ = cmd::run("nft", &["delete", "table", family, NFT_TABLE]);
        }
    }
}

/// Whether a kill switch was left behind by a dvpn that didn't shut down cleanly (it
/// crashed or was killed while connected). The service then resumes the connection
/// instead of unblocking traffic.
pub fn kill_switch_left_behind() -> bool {
    cmd::run("nft", &["list", "table", "ip", NFT_TABLE]).is_ok()
}

/// Removes a kill switch left behind by a dvpn that didn't shut down cleanly, unless
/// another dvpn runs in this network namespace (it may be its).
pub fn recover_stale_state() {
    if !kill_switch_left_behind() && !blackholes_present() && !dns_redirect_present() {
        return;
    }
    if super::other_dvpn_in_this_namespace() {
        return;
    }
    delete_tables();
    delete_dns_redirect();
    for half in IPV6_BLACKHOLES {
        let _ = cmd::run("ip", &["-6", "route", "del", "blackhole", half]);
    }
    warn!("removed a kill switch left behind by a dvpn that didn't shut down cleanly");
}

fn dns_redirect_present() -> bool {
    cmd::run("nft", &["list", "table", "ip", DNS_TABLE]).is_ok()
}

fn delete_dns_redirect() {
    if dns_redirect_present() {
        let _ = cmd::run("nft", &["delete", "table", "ip", DNS_TABLE]);
    }
}

/// Sends DNS that would leave outside `dev` to `dns` through the tunnel instead: plain
/// DNS is redirected (whatever resolver it was meant for answers from `dns` now), DNS
/// over TLS refused (it can't be redirected; the client falls back or fails). Queries
/// already routed into the tunnel are left alone.
pub fn dns_redirect_ruleset(dev: &str, dns: Ipv4Addr) -> String {
    format!(
        r#"table ip {DNS_TABLE} {{
    chain stray_dns {{
        type nat hook output priority dstnat; policy accept;
        oifname != {{ "lo", "{dev}" }} meta l4proto {{ tcp, udp }} th dport 53 dnat to {dns}
    }}
    chain stray_dot {{
        type filter hook output priority filter; policy accept;
        oifname != {{ "lo", "{dev}" }} meta l4proto {{ tcp, udp }} th dport 853 reject
    }}
}}
"#
    )
}

fn blackholes_present() -> bool {
    cmd::run("ip", &["-6", "route", "show", "type", "blackhole"])
        .is_ok_and(|out| IPV6_BLACKHOLES.iter().any(|half| out.lines().any(|l| l.starts_with(&format!("blackhole {half}")))))
}

/// `(level, path)` of this process's cgroup (v2), e.g. `(2, "system.slice/dvpn.service")`,
/// which nftables can match to recognise dvpn's own packets. `None` without cgroup v2,
/// in the root cgroup (that would match everything), or for a path nftables can't quote.
fn own_cgroup() -> Option<(usize, String)> {
    parse_cgroup(&std::fs::read_to_string("/proc/self/cgroup").ok()?)
}

fn parse_cgroup(proc_cgroup: &str) -> Option<(usize, String)> {
    let path = proc_cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim().trim_start_matches('/');
    let quotable = path.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@:/".contains(c));
    if path.is_empty() || !quotable {
        return None;
    }
    Some((path.split('/').count(), path.to_string()))
}

/// The standard local ranges plus the (narrow enough) networks this host is attached to.
fn lan_networks() -> Vec<Ipv4Net> {
    let mut nets: Vec<Ipv4Net> = LAN_V4.iter().map(|n| n.parse().expect("valid CIDR")).collect();
    if let Ok(attached) = net::local_ipv4_networks() {
        nets.extend(attached.into_iter().filter(|n| n.prefix_len() >= MIN_LAN_PREFIX));
    }
    nets.sort();
    nets.dedup();
    // nftables refuses overlapping elements in an interval set.
    let all = nets.clone();
    nets.retain(|n| !all.iter().any(|other| other != n && other.contains(n)));
    nets
}

/// The kill switch's firewall. With `cgroup`, outgoing traffic is filtered: it may
/// leave only through `dev` (the tunnel), to the LAN, as dvpn's own traffic, or as a
/// reply to a connection someone else started (peers dialing this node). Without it,
/// only the inbound part is installed.
pub fn ruleset(dev: &str, cgroup: Option<(usize, &str)>, lan: &[Ipv4Net]) -> String {
    let inbound = format!(
        r#"    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "{dev}" ct state established,related accept
        iifname "{dev}" drop
    }}"#
    );
    let Some((level, path)) = cgroup else {
        return format!("table ip {NFT_TABLE} {{\n{inbound}\n}}\n");
    };
    let lan = lan.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    let own = format!(r#"socket cgroupv2 level {level} "{path}" accept"#);
    format!(
        r#"table ip {NFT_TABLE} {{
    set lan {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {lan} }}
    }}
{inbound}
    chain output {{
        type filter hook output priority filter; policy accept;
        oifname {{ "lo", "{dev}", "{exit_tun}" }} accept
        ct direction reply accept
        {own}
        ip daddr @lan accept
        icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
        reject with icmp type admin-prohibited
    }}
}}
table ip6 {NFT_TABLE} {{
    chain output {{
        type filter hook output priority filter; policy accept;
        oifname "lo" accept
        ct direction reply accept
        {own}
        ip6 daddr {{ fe80::/10, ff00::/8, fc00::/7 }} accept
        icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-report, mld2-listener-report }} accept
        reject with icmpv6 type admin-prohibited
    }}
}}
"#,
        exit_tun = crate::lend::EXIT_TUN,
    )
}

/// Routes all IPv4 traffic into the tunnel; see the module docs.
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
    /// Routes all IPv4 traffic into `dev`. With `dns`, the tunnel's DNS server is set
    /// via systemd-resolved, encrypted as `dot` says.
    pub fn install(dev: &str, dns: Option<Ipv4Addr>, dot: DnsOverTls) -> anyhow::Result<Self> {
        if !super::valid_interface_name(dev) {
            bail!("invalid TUN device name {dev:?}");
        }
        let mut guard = Self {
            dev: dev.to_string(),
            original_default: net::default_route()?,
            exempted: HashSet::new(),
            undo: Vec::new(),
            warnings: Vec::new(),
        };
        for half in CAPTURE_ROUTES {
            guard.apply("ip", &["-4", "route", "add", half, "dev", dev], &["-4", "route", "del", half, "dev", dev])?;
        }
        if let Some(dns) = dns {
            guard.pin_dns(dns, dot);
        }
        Ok(guard)
    }

    fn pin_dns(&mut self, dns: Ipv4Addr, dot: DnsOverTls) {
        let dev = self.dev.clone();
        let server = if dot == DnsOverTls::No { dns.to_string() } else { dns_server_spec(dns) };
        let configured = cmd::run("resolvectl", &["dns", &dev, &server])
            .and_then(|_| cmd::run("resolvectl", &["domain", &dev, "~."]));
        // Also when resolved isn't used or failed: the redirect alone keeps DNS in the tunnel.
        delete_dns_redirect();
        let redirected = cmd::run_with_stdin("nft", &["-f", "-"], Some(&dns_redirect_ruleset(&dev, dns)));
        match &redirected {
            Ok(_) => self.undo.push(("nft", vec!["delete".into(), "table".into(), "ip".into(), DNS_TABLE.into()])),
            Err(e) => warn!("could not redirect stray DNS into the tunnel: {e:#}"),
        }
        if let Err(e) = configured {
            if redirected.is_err() {
                self.warn(&format!("could not configure DNS ({e:#}); DNS queries may leak outside the tunnel"));
            } else {
                warn!("could not configure systemd-resolved ({e:#}); DNS is redirected into the tunnel instead, unencrypted");
            }
            return;
        }
        self.undo.push(("resolvectl", vec!["revert".into(), dev.clone()]));
        let encrypted = match cmd::run("resolvectl", &["dnsovertls", &dev, resolvectl_value(dot)]) {
            Ok(_) => dot != DnsOverTls::No,
            Err(e) => {
                if dot != DnsOverTls::No {
                    self.warn(&format!("DNS through the tunnel isn't encrypted, so the exit can read it ({e:#})"));
                }
                false
            }
        };
        let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        if uses_resolved_stub(&resolv_conf) {
            info!(encrypted, "DNS goes through the tunnel");
        } else if redirected.is_ok() {
            // Programs ask another resolver, whose queries are redirected: in the tunnel,
            // but unencrypted, since only systemd-resolved does DNS over TLS.
            info!("/etc/resolv.conf doesn't use systemd-resolved; DNS is redirected into the tunnel, unencrypted");
            if dot != DnsOverTls::No {
                self.warn(
                    "DNS goes through the tunnel but isn't encrypted, so the exit can read it: \
                     /etc/resolv.conf doesn't use systemd-resolved (127.0.0.53), which encrypts it",
                );
            }
        } else {
            self.warn(
                "/etc/resolv.conf doesn't use systemd-resolved, so DNS queries may go to your \
                 local resolver outside the tunnel; point it at 127.0.0.53 or set DNS yourself",
            );
        }
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
            cmd::run("ip", &["-4", "route", "replace", half, "dev", &self.dev])?;
        }
        Ok(())
    }

    /// Keeps `ip` (an entry relay) on its original route, so the tunnel's own
    /// traffic doesn't loop into the tunnel. With the kill switch filtering output,
    /// only dvpn itself can use that route.
    pub fn exempt(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        if !self.exempted.insert(ip) {
            return Ok(());
        }
        let current = net::route_get(ip)?;
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
        cmd::run(program, args)?;
        self.undo.push((program, undo.iter().map(|s| s.to_string()).collect()));
        Ok(())
    }
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
            if let Err(e) = cmd::run(program, &args) {
                warn!("cleanup step failed: {e:#}");
            }
        }
        info!("routes restored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lan() -> Vec<Ipv4Net> {
        vec!["192.168.0.0/16".parse().unwrap(), "198.51.100.0/24".parse().unwrap()]
    }

    #[test]
    fn inbound_firewall_only_lets_replies_in() {
        for rules in [ruleset("dvpn0", None, &[]), ruleset("dvpn0", Some((2, "system.slice/dvpn.service")), &lan())] {
            assert!(rules.contains(r#"iifname "dvpn0" ct state established,related accept"#));
            assert!(rules.contains(r#"iifname "dvpn0" drop"#));
            let accept = rules.find("accept\n        iifname").unwrap();
            assert!(accept < rules.find(r#"iifname "dvpn0" drop"#).unwrap(), "replies must be accepted before the drop");
        }
        assert!(!ruleset("dvpn0", None, &[]).contains("chain output"), "without a cgroup, output isn't filtered");
    }

    #[test]
    fn outgoing_traffic_leaves_only_through_the_tunnel() {
        let rules = ruleset("dvpn0", Some((2, "system.slice/dvpn.service")), &lan());
        let output = &rules[rules.find("chain output").unwrap()..];
        // Allowed first, then everything else is refused.
        let allowed = [
            r#"oifname { "lo", "dvpn0", "dvpn-exit" } accept"#,
            "ct direction reply accept",
            r#"socket cgroupv2 level 2 "system.slice/dvpn.service" accept"#,
            "ip daddr @lan accept",
        ];
        let reject = output.find("reject with icmp type admin-prohibited").unwrap();
        for rule in allowed {
            assert!(output.find(rule).unwrap() < reject, "{rule}");
        }
        assert!(rules.contains("elements = { 192.168.0.0/16, 198.51.100.0/24 }"));
        // IPv6 is refused too, apart from the link itself.
        let v6 = &rules[rules.find("table ip6").unwrap()..];
        assert!(v6.contains("reject with icmpv6 type admin-prohibited"));
        assert!(v6.contains(r#"socket cgroupv2 level 2 "system.slice/dvpn.service" accept"#));
        assert!(!v6.contains("dvpn0"), "IPv6 doesn't go through the tunnel at all");
    }

    #[test]
    fn finds_the_cgroup_to_exempt() {
        assert_eq!(parse_cgroup("0::/system.slice/dvpn.service\n"), Some((2, "system.slice/dvpn.service".into())));
        assert_eq!(
            parse_cgroup("12:cpu:/x\n0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some((3, "user.slice/user-1000.slice/session-3.scope".into()))
        );
        assert_eq!(parse_cgroup("0::/\n"), None, "the root cgroup would exempt everything");
        assert_eq!(parse_cgroup("1:name=systemd:/foo\n"), None, "cgroup v1 only");
        assert_eq!(parse_cgroup("0::/a\"b\n"), None, "unquotable");
    }

    #[test]
    fn stray_dns_is_sent_into_the_tunnel() {
        let rules = dns_redirect_ruleset("dvpn0", Ipv4Addr::new(9, 9, 9, 9));
        assert!(rules.contains("type nat hook output priority dstnat"));
        assert!(rules.contains(r#"oifname != { "lo", "dvpn0" } meta l4proto { tcp, udp } th dport 53 dnat to 9.9.9.9"#));
        assert!(rules.contains(r#"oifname != { "lo", "dvpn0" } meta l4proto { tcp, udp } th dport 853 reject"#));
        crate::platform::linux::assert_nft_parses(&rules);
    }

    #[test]
    fn kill_switch_rulesets_parse() {
        crate::platform::linux::assert_nft_parses(&ruleset("dvpn0", None, &[]));
        crate::platform::linux::assert_nft_parses(&ruleset("dvpn0", Some((2, "system.slice/dvpn.service")), &lan()));
    }

    #[test]
    fn well_known_resolvers_get_their_tls_name() {
        assert_eq!(dns_server_spec(Ipv4Addr::new(9, 9, 9, 9)), "9.9.9.9#dns.quad9.net");
        assert_eq!(dns_server_spec(Ipv4Addr::new(192, 0, 2, 53)), "192.0.2.53");
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
