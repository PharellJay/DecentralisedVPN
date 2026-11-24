//! The host's routes and networks, read from the kernel over netlink
//! ([`super::netlink`]); no `ip` processes.

use std::net::Ipv4Addr;

use anyhow::Context;
use ipnet::Ipv4Net;

use super::netlink;

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
#[cfg(test)]
pub fn parse_next_hop(line: &str) -> Option<NextHop> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| tokens.windows(2).find(|w| w[0] == key).map(|w| w[1]);
    Some(NextHop {
        via: after("via").and_then(|v| v.parse().ok()),
        dev: after("dev")?.to_string(),
    })
}

/// The next hop of `route`; `None` without an outgoing interface (e.g. unreachable).
fn next_hop(route: Option<netlink::Route>) -> anyhow::Result<Option<NextHop>> {
    let Some(route) = route else { return Ok(None) };
    let Some(oif) = route.oif else { return Ok(None) };
    let dev = netlink::interface_name(oif).context("reading interface names")?;
    Ok(dev.map(|dev| NextHop { via: route.gateway, dev }))
}

/// The route the kernel would currently use to reach `ip`.
pub fn route_get(ip: Ipv4Addr) -> anyhow::Result<Option<NextHop>> {
    next_hop(netlink::route_to(ip).context("looking up a route")?)
}

/// The main table's default route (with the lowest metric, if there are several).
pub fn default_route() -> anyhow::Result<Option<NextHop>> {
    next_hop(netlink::default_route().context("reading the routing table")?)
}

/// Parses `inet a.b.c.d/nn` entries from `ip -o -4 addr show` output.
#[cfg(test)]
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
    Ok(netlink::ipv4_addresses()
        .context("reading this host's addresses")?
        .into_iter()
        .filter_map(|(ip, len)| Ipv4Net::new(ip, len).ok())
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

    /// Netlink answers as `ip` does, where it's installed.
    #[test]
    fn routes_match_iproute2() {
        let ip = |args: &[&str]| {
            std::process::Command::new("ip").args(args).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        };
        let Some(default) = ip(&["-4", "route", "show", "default"]) else { return };
        assert_eq!(default_route().unwrap(), default.lines().next().and_then(parse_next_hop));
        let target = Ipv4Addr::new(9, 9, 9, 9);
        let get = ip(&["-4", "route", "get", &target.to_string()]).unwrap_or_default();
        assert_eq!(route_get(target).unwrap(), get.lines().next().and_then(parse_next_hop));
        assert!(local_ipv4_networks().unwrap().contains(&"127.0.0.0/8".parse().unwrap()));
    }

    #[test]
    fn parses_addresses() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                   2: eth0    inet 198.51.100.20/24 brd 198.51.100.255 scope global eth0\\ ...\n";
        let nets: Vec<String> = parse_ipv4_networks(out).iter().map(|n| n.trunc().to_string()).collect();
        assert_eq!(nets, ["127.0.0.0/8", "198.51.100.0/24"]);
    }
}
