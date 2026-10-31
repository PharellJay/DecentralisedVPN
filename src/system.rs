//! Thin wrappers around `ip` (iproute2). Route and address changes need root.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, bail};
use ipnet::Ipv4Net;

pub fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("could not run {program}"))?;
    if !out.status.success() {
        bail!("`{program} {}` failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Next hop of a route: an optional gateway and the outgoing device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    pub via: Option<Ipv4Addr>,
    pub dev: String,
}

impl NextHop {
    /// Arguments for `ip route ... <these>`.
    pub fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(via) = self.via {
            args.extend(["via".to_string(), via.to_string()]);
        }
        args.extend(["dev".to_string(), self.dev.clone()]);
        args
    }
}

/// Parses `... via <gw> dev <dev> ...` from one line of `ip route` output.
pub fn parse_next_hop(line: &str) -> Option<NextHop> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| tokens.windows(2).find(|w| w[0] == key).map(|w| w[1]);
    Some(NextHop {
        via: after("via").and_then(|v| v.parse().ok()),
        dev: after("dev")?.to_string(),
    })
}

/// The route the kernel would currently use to reach `ip`.
pub fn route_get(ip: Ipv4Addr) -> anyhow::Result<Option<NextHop>> {
    Ok(run("ip", &["-4", "route", "get", &ip.to_string()])?.lines().next().and_then(parse_next_hop))
}

pub fn default_route() -> anyhow::Result<Option<NextHop>> {
    Ok(run("ip", &["-4", "route", "show", "default"])?.lines().next().and_then(parse_next_hop))
}

/// Parses `inet a.b.c.d/nn` entries from `ip -o -4 addr show` output.
pub fn parse_ipv4_networks(output: &str) -> Vec<Ipv4Net> {
    output
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let cidr = tokens.windows(2).find(|w| w[0] == "inet")?[1];
            cidr.parse().ok()
        })
        .collect()
}

/// Every IPv4 network this host is attached to (including its own addresses).
pub fn local_ipv4_networks() -> anyhow::Result<Vec<Ipv4Net>> {
    Ok(parse_ipv4_networks(&run("ip", &["-o", "-4", "addr", "show"])?)
        .into_iter()
        .map(|net| net.trunc())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_routes() {
        let hop = parse_next_hop("198.51.100.10 via 192.168.1.1 dev eth0 src 192.168.1.2 uid 0").unwrap();
        assert_eq!(hop.via, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hop.dev, "eth0");
        assert_eq!(hop.args(), ["via", "192.168.1.1", "dev", "eth0"]);

        let on_link = parse_next_hop("192.168.1.5 dev wlan0 src 192.168.1.2 uid 1000").unwrap();
        assert_eq!(on_link.via, None);
        assert_eq!(on_link.args(), ["dev", "wlan0"]);

        assert!(parse_next_hop("unreachable 10.0.0.1").is_none());
    }

    #[test]
    fn parses_addresses() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                   2: eth0    inet 198.51.100.20/24 brd 198.51.100.255 scope global eth0\\ ...\n";
        let nets: Vec<String> = parse_ipv4_networks(out).iter().map(|n| n.trunc().to_string()).collect();
        assert_eq!(nets, ["127.0.0.0/8", "198.51.100.0/24"]);
    }
}
