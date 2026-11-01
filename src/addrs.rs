//! Multiaddr helpers: public-IP checks, relay-circuit detection, /16 diversity, and
//! redacting addresses from text that may end up in logs or status output.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;

pub fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

pub fn is_circuit(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// True if the address's IP is routable on the public internet.
pub fn is_public(addr: &Multiaddr) -> bool {
    match ip_of(addr) {
        Some(IpAddr::V4(ip)) => is_public_v4(ip),
        Some(IpAddr::V6(ip)) => is_public_v6(ip),
        None => false,
    }
}

pub fn is_unspecified(addr: &Multiaddr) -> bool {
    ip_of(addr).is_some_and(|ip| ip.is_unspecified())
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (a == 100 && (64..128).contains(&b)) // CGNAT 100.64.0.0/10
        || a == 0
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
        || ip.to_ipv4_mapped().is_some_and(|v4| !is_public_v4(v4)))
}

/// Whether a node should dial `addr` for someone else (a splice request): relay-circuit
/// addresses and public IPs only, so a client can't make a relay connect to its own
/// loopback or LAN.
pub fn is_dialable_for_others(addr: &Multiaddr, allow_private: bool) -> bool {
    allow_private || is_circuit(addr) || is_public(addr)
}

/// Replaces the host part of every multiaddr in `text` (`/ip4/…`, `/ip6/…`, `/dns…/…`)
/// with `<redacted>`. libp2p's error messages embed peers' addresses, and those must
/// never reach logs or status output.
pub fn redact(text: &str) -> String {
    const HOSTS: [&str; 6] = ["/ip4/", "/ip6/", "/dns/", "/dns4/", "/dns6/", "/dnsaddr/"];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((at, marker)) = HOSTS.iter().filter_map(|m| rest.find(m).map(|i| (i, *m))).min() {
        out.push_str(&rest[..at + marker.len()]);
        rest = &rest[at + marker.len()..];
        let end = rest
            .find(|c: char| c == '/' || c.is_whitespace() || "\"',)]}>".contains(c))
            .unwrap_or(rest.len());
        out.push_str("<redacted>");
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// True if any public IPv4 address in `a` shares a /16 with one in `b`.
///
/// Non-public addresses can't be judged and are ignored; relay-circuit addresses
/// carry the relay's IP, which is exactly what should be compared.
pub fn same_slash16(a: &[Multiaddr], b: &[Multiaddr]) -> bool {
    let prefixes = |addrs: &[Multiaddr]| -> HashSet<[u8; 2]> {
        addrs
            .iter()
            .filter_map(ip_of)
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) if is_public_v4(v4) => Some([v4.octets()[0], v4.octets()[1]]),
                _ => None,
            })
            .collect()
    };
    !prefixes(a).is_disjoint(&prefixes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_every_address_in_a_message() {
        let error = "Failed to negotiate transport protocol(s): [(/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWX: \
                     Connection refused), (/ip6/2001:db8::1/udp/4001/quic-v1: timeout), (/dns4/relay.example.org/tcp/1)]";
        let redacted = redact(error);
        for secret in ["203.0.113.7", "2001:db8::1", "relay.example.org"] {
            assert!(!redacted.contains(secret), "{secret} leaked: {redacted}");
        }
        assert!(redacted.contains("/ip4/<redacted>/tcp/4001/p2p/12D3KooWX"), "{redacted}");
        assert!(redacted.contains("Connection refused"));
        assert_eq!(redact("no addresses here"), "no addresses here");
    }

    #[test]
    fn relays_only_dial_public_or_circuit_addresses_for_others() {
        assert!(is_dialable_for_others(&ma("/ip4/203.0.114.1/tcp/4001"), false));
        assert!(is_dialable_for_others(&ma("/ip4/203.0.114.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"), false));
        for internal in ["/ip4/127.0.0.1/tcp/22", "/ip4/192.168.1.1/tcp/80", "/ip4/10.0.0.5/tcp/4001", "/ip6/::1/tcp/631", "/ip4/169.254.169.254/tcp/80"] {
            assert!(!is_dialable_for_others(&ma(internal), false), "{internal}");
            assert!(is_dialable_for_others(&ma(internal), true), "allowed with --allow-private-addrs");
        }
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_public_and_private() {
        assert!(is_public(&ma("/ip4/203.0.114.1/tcp/1")));
        assert!(!is_public(&ma("/ip4/192.168.1.5/tcp/1")));
        assert!(!is_public(&ma("/ip4/127.0.0.1/tcp/1")));
        assert!(!is_public(&ma("/ip4/100.64.3.3/tcp/1")));
        assert!(!is_public(&ma("/ip6/fe80::1/tcp/1")));
        assert!(is_public(&ma("/ip6/2a01:4f8::1/tcp/1")));
    }

    #[test]
    fn detects_shared_slash16() {
        let a = [ma("/ip4/81.2.3.4/tcp/1")];
        assert!(same_slash16(&a, &[ma("/ip4/81.2.200.9/udp/1/quic-v1")]));
        assert!(!same_slash16(&a, &[ma("/ip4/81.3.3.4/tcp/1")]));
        // Private addresses never count as "same subnet".
        assert!(!same_slash16(&[ma("/ip4/127.0.0.1/tcp/1")], &[ma("/ip4/127.0.0.1/tcp/2")]));
    }
}
