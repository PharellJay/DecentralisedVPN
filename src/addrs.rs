//! Multiaddr helpers: public-IP checks, relay-circuit detection and /16 diversity.

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
