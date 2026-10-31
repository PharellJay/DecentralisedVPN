//! Exit policy: what a client may send out through an exit. See docs/DESIGN.md §3.6.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::packet::{self, PROTO_TCP};

/// Never reachable through an exit: private, loopback, link-local, CGNAT, multicast,
/// reserved and other clients' virtual addresses (inside 10.0.0.0/8).
const DEFAULT_DENY: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

pub const DEFAULT_BLOCKED_TCP_PORTS: &[u16] = &[25];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    Malformed,
    /// Source address isn't the one assigned to this session.
    Spoofed,
    Destination,
    Port,
    /// Non-first TCP fragments can't be port-checked.
    Fragment,
}

#[derive(Debug, Clone)]
pub struct ExitPolicy {
    deny: Vec<Ipv4Net>,
    pub blocked_tcp_ports: Vec<u16>,
}

impl ExitPolicy {
    /// Default policy plus `extra_deny` (e.g. the exit host's own networks).
    pub fn new(extra_deny: impl IntoIterator<Item = Ipv4Net>, blocked_tcp_ports: Vec<u16>) -> Self {
        let mut deny: Vec<Ipv4Net> = DEFAULT_DENY.iter().map(|n| n.parse().expect("valid CIDR")).collect();
        deny.extend(extra_deny);
        Self {
            deny,
            blocked_tcp_ports,
        }
    }

    /// Checks a packet sent by the client that was assigned `assigned`.
    pub fn check(&self, packet: &[u8], assigned: Ipv4Addr) -> Result<(), Denied> {
        let info = packet::parse(packet).ok_or(Denied::Malformed)?;
        if info.src != assigned {
            return Err(Denied::Spoofed);
        }
        if self.deny.iter().any(|net| net.contains(&info.dst)) {
            return Err(Denied::Destination);
        }
        if info.protocol == PROTO_TCP {
            match info.dst_port {
                Some(port) if self.blocked_tcp_ports.contains(&port) => return Err(Denied::Port),
                None if info.fragmented => return Err(Denied::Fragment),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PROTO_UDP;
    use crate::packet::tests::ipv4;

    const CLIENT: [u8; 4] = [10, 77, 0, 2];

    fn policy() -> ExitPolicy {
        ExitPolicy::new(["198.51.100.0/24".parse().unwrap()], DEFAULT_BLOCKED_TCP_PORTS.to_vec())
    }

    fn check(src: [u8; 4], dst: [u8; 4], proto: u8, port: u16) -> Result<(), Denied> {
        policy().check(&ipv4(src, dst, proto, port), Ipv4Addr::from(CLIENT))
    }

    #[test]
    fn allows_public_destinations() {
        assert_eq!(check(CLIENT, [93, 184, 216, 34], PROTO_TCP, 443), Ok(()));
        assert_eq!(check(CLIENT, [9, 9, 9, 9], PROTO_UDP, 53), Ok(()));
    }

    #[test]
    fn blocks_spoofed_sources() {
        assert_eq!(check([10, 77, 0, 3], [93, 184, 216, 34], PROTO_TCP, 443), Err(Denied::Spoofed));
        assert_eq!(check([8, 8, 8, 8], [93, 184, 216, 34], PROTO_TCP, 443), Err(Denied::Spoofed));
    }

    #[test]
    fn blocks_private_and_exit_local_destinations() {
        for dst in [[192, 168, 1, 1], [10, 77, 0, 3], [127, 0, 0, 1], [169, 254, 169, 254], [172, 20, 0, 1]] {
            assert_eq!(check(CLIENT, dst, PROTO_TCP, 80), Err(Denied::Destination), "{dst:?}");
        }
        // The exit host's own network, added as an extra deny.
        assert_eq!(check(CLIENT, [198, 51, 100, 20], PROTO_TCP, 22), Err(Denied::Destination));
    }

    #[test]
    fn blocks_smtp_but_not_udp_25() {
        assert_eq!(check(CLIENT, [93, 184, 216, 34], PROTO_TCP, 25), Err(Denied::Port));
        assert_eq!(check(CLIENT, [93, 184, 216, 34], PROTO_UDP, 25), Ok(()));
    }

    #[test]
    fn blocks_later_tcp_fragments() {
        let mut p = ipv4(CLIENT, [93, 184, 216, 34], PROTO_TCP, 25);
        p[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        assert_eq!(policy().check(&p, Ipv4Addr::from(CLIENT)), Err(Denied::Fragment));
    }

    #[test]
    fn rejects_non_ipv4() {
        assert_eq!(policy().check(&[0x60; 40], Ipv4Addr::from(CLIENT)), Err(Denied::Malformed));
    }
}
