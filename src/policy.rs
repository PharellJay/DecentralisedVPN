//! Exit policy: what a client may send out through an exit. See docs/DESIGN.md §3.6.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use ipnet::Ipv4Net;

use crate::addrs;
use crate::packet::{self, Ipv4Info, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::records::ExitKind;

/// How many of this exit's own public addresses are remembered (see [`SelfAddrs`]).
const MAX_SELF_ADDRS: usize = 16;

pub const DEFAULT_BLOCKED_TCP_PORTS: &[u16] = &[25];

/// TCP port ranges users' exits forward: a "reduced exit policy" in the spirit of Tor's.
/// Everyday services work; what draws abuse complaints (file sharing, scanning, spam,
/// brute-forcing remote desktops and databases) mostly doesn't.
pub const REDUCED_TCP_PORTS: &[(u16, u16)] = &[
    (22, 22),       // SSH
    (43, 43),       // whois
    (53, 53),       // DNS
    (80, 80),       // HTTP
    (110, 110),     // POP3
    (143, 143),     // IMAP
    (443, 443),     // HTTPS
    (465, 465),     // mail submission (TLS)
    (587, 587),     // mail submission
    (853, 853),     // DNS over TLS
    (873, 873),     // rsync
    (993, 993),     // IMAPS
    (995, 995),     // POP3S
    (1194, 1194),   // OpenVPN
    (5222, 5223),   // XMPP
    (5228, 5228),   // Android push
    (6697, 6697),   // IRC (TLS)
    (8000, 8000),   // HTTP alternatives
    (8008, 8008),
    (8080, 8080),
    (8443, 8443),
    (8888, 8888),
    (9418, 9418),   // git
    (11371, 11371), // OpenPGP keyservers
    (64738, 64738), // Mumble
];

/// UDP port ranges users' exits forward.
pub const REDUCED_UDP_PORTS: &[(u16, u16)] = &[
    (53, 53),       // DNS
    (123, 123),     // NTP
    (443, 443),     // QUIC (HTTP/3)
    (853, 853),     // DNS over QUIC
    (3478, 3478),   // STUN/TURN, for calls
    (19302, 19309), // Google STUN
    (64738, 64738), // Mumble
];

/// Which destination ports an exit forwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ports {
    /// Every port and protocol except these TCP ports: dedicated exits, run by
    /// operators who chose to.
    AllExcept(Vec<u16>),
    /// Only [`REDUCED_TCP_PORTS`], [`REDUCED_UDP_PORTS`] and ICMP: users' exits, whose
    /// lenders didn't sign up to answer for arbitrary traffic.
    Reduced,
}

impl Ports {
    pub fn for_kind(kind: ExitKind) -> Self {
        match kind {
            ExitKind::Dedicated => Ports::AllExcept(DEFAULT_BLOCKED_TCP_PORTS.to_vec()),
            ExitKind::User => Ports::Reduced,
        }
    }

    fn check(&self, info: &Ipv4Info) -> Result<(), Denied> {
        let in_ranges = |ranges: &[(u16, u16)], port: u16| ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&port));
        match self {
            Ports::AllExcept(blocked) => match (info.protocol, info.dst_port) {
                (PROTO_TCP, Some(port)) if blocked.contains(&port) => Err(Denied::Port),
                (PROTO_TCP, None) if info.fragmented => Err(Denied::Fragment),
                _ => Ok(()),
            },
            Ports::Reduced => {
                let ranges = match info.protocol {
                    PROTO_TCP => REDUCED_TCP_PORTS,
                    PROTO_UDP => REDUCED_UDP_PORTS,
                    PROTO_ICMP => return Ok(()),
                    _ => return Err(Denied::Protocol),
                };
                match info.dst_port {
                    Some(port) if in_ranges(ranges, port) => Ok(()),
                    Some(_) => Err(Denied::Port),
                    None if info.fragmented => Err(Denied::Fragment),
                    None => Err(Denied::Malformed),
                }
            }
        }
    }

    /// The same restriction as nftables rules for the exit's forward chain.
    pub fn nft_rules(&self, tun: &str) -> String {
        let list = |ranges: &[(u16, u16)]| {
            ranges
                .iter()
                .map(|&(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self {
            Ports::AllExcept(blocked) if blocked.is_empty() => String::new(),
            Ports::AllExcept(blocked) => {
                let ports = blocked.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
                format!("\n        iifname \"{tun}\" tcp dport {{ {ports} }} drop")
            }
            Ports::Reduced => format!(
                "\n        iifname \"{tun}\" meta l4proto != {{ tcp, udp, icmp }} drop\
                 \n        iifname \"{tun}\" tcp dport != {{ {} }} drop\
                 \n        iifname \"{tun}\" udp dport != {{ {} }} drop",
                list(REDUCED_TCP_PORTS),
                list(REDUCED_UDP_PORTS)
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    Malformed,
    /// Source address isn't the one assigned to this session.
    Spoofed,
    Destination,
    Port,
    /// Neither TCP, UDP nor ICMP, on an exit with [`Ports::Reduced`].
    Protocol,
    /// Non-first TCP fragments can't be port-checked.
    Fragment,
}

/// This exit's own public addresses, as peers see them. Behind a home router that's the
/// router's WAN address, which isn't on any of this host's interfaces: without denying
/// it, a client could reach port forwards into the lender's LAN, or the router itself,
/// through hairpin NAT. Updated while lending runs; the oldest addresses drop out.
#[derive(Debug, Clone, Default)]
pub struct SelfAddrs(Arc<RwLock<VecDeque<Ipv4Addr>>>);

impl SelfAddrs {
    /// Adds `ip` if it's new; returns whether it was.
    pub fn add(&self, ip: Ipv4Addr) -> bool {
        let mut addrs = self.0.write().expect("self addrs lock");
        if addrs.contains(&ip) {
            return false;
        }
        if addrs.len() >= MAX_SELF_ADDRS {
            addrs.pop_front();
        }
        addrs.push_back(ip);
        true
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.0.read().expect("self addrs lock").contains(&ip)
    }
}

#[derive(Debug, Clone)]
pub struct ExitPolicy {
    deny: Vec<Ipv4Net>,
    pub ports: Ports,
    pub self_addrs: SelfAddrs,
}

impl ExitPolicy {
    /// Never reachable through an exit: every special-purpose range (private, loopback,
    /// link-local, CGNAT, multicast, documentation, reserved; other clients' virtual
    /// addresses are inside 10.0.0.0/8), plus `extra_deny` (e.g. the exit host's own
    /// networks) and the exit's own public addresses ([`SelfAddrs`]).
    pub fn new(extra_deny: impl IntoIterator<Item = Ipv4Net>, ports: Ports) -> Self {
        let mut deny = addrs::special_purpose_v4();
        deny.extend(extra_deny);
        Self {
            deny,
            ports,
            self_addrs: SelfAddrs::default(),
        }
    }

    /// Checks a packet sent by the client that was assigned `assigned`.
    pub fn check(&self, packet: &[u8], assigned: Ipv4Addr) -> Result<(), Denied> {
        let info = packet::parse(packet).ok_or(Denied::Malformed)?;
        if info.src != assigned {
            return Err(Denied::Spoofed);
        }
        if self.deny.iter().any(|net| net.contains(&info.dst)) || self.self_addrs.contains(info.dst) {
            return Err(Denied::Destination);
        }
        self.ports.check(&info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::ipv4;

    const CLIENT: [u8; 4] = [10, 77, 0, 2];

    fn policy() -> ExitPolicy {
        ExitPolicy::new(["198.51.100.0/24".parse().unwrap()], Ports::for_kind(ExitKind::Dedicated))
    }

    fn check_reduced(proto: u8, port: u16) -> Result<(), Denied> {
        let policy = ExitPolicy::new([], Ports::for_kind(ExitKind::User));
        policy.check(&ipv4(CLIENT, [93, 184, 216, 34], proto, port), Ipv4Addr::from(CLIENT))
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
    fn blocks_the_exits_own_public_address() {
        let policy = policy();
        let router = [81, 2, 3, 4];
        let packet = ipv4(CLIENT, router, PROTO_TCP, 8080);
        assert_eq!(policy.check(&packet, Ipv4Addr::from(CLIENT)), Ok(()));
        assert!(policy.self_addrs.add(Ipv4Addr::from(router)));
        assert!(!policy.self_addrs.add(Ipv4Addr::from(router)), "already known");
        assert_eq!(policy.check(&packet, Ipv4Addr::from(CLIENT)), Err(Denied::Destination), "hairpin NAT into the LAN");
        for i in 0..MAX_SELF_ADDRS as u8 {
            policy.self_addrs.add(Ipv4Addr::new(81, 9, 9, i));
        }
        assert!(!policy.self_addrs.contains(Ipv4Addr::from(router)), "the oldest address drops out");
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
    fn users_exits_forward_only_common_ports() {
        for (proto, port) in [(PROTO_TCP, 443), (PROTO_TCP, 80), (PROTO_TCP, 22), (PROTO_TCP, 5223), (PROTO_UDP, 443), (PROTO_UDP, 53), (PROTO_UDP, 19305)] {
            assert_eq!(check_reduced(proto, port), Ok(()), "{proto}/{port}");
        }
        // Torrents, SMTP, remote desktop, databases; ports outside a range's ends.
        for (proto, port) in [(PROTO_TCP, 6881), (PROTO_TCP, 25), (PROTO_TCP, 3389), (PROTO_TCP, 5432), (PROTO_UDP, 6881), (PROTO_TCP, 5224), (PROTO_UDP, 19310)] {
            assert_eq!(check_reduced(proto, port), Err(Denied::Port), "{proto}/{port}");
        }
        assert_eq!(check_reduced(PROTO_ICMP, 0), Ok(()), "ping works");
        assert_eq!(check_reduced(47, 0), Err(Denied::Protocol), "GRE");
        assert_eq!(check(CLIENT, [93, 184, 216, 34], 47, 0), Ok(()), "dedicated exits forward other protocols");
    }

    #[test]
    fn firewall_rules_match_the_port_policy() {
        let rules = Ports::Reduced.nft_rules("dvpn-exit");
        assert!(rules.contains(r#"iifname "dvpn-exit" meta l4proto != { tcp, udp, icmp } drop"#), "{rules}");
        assert!(rules.contains(r#"tcp dport != { 22, 43, 53, 80,"#), "{rules}");
        assert!(rules.contains("5222-5223"), "{rules}");
        assert!(rules.contains(r#"udp dport != { 53, 123, 443, 853, 3478, 19302-19309, 64738 } drop"#), "{rules}");
        assert_eq!(Ports::AllExcept(vec![25]).nft_rules("t"), "\n        iifname \"t\" tcp dport { 25 } drop");
        assert_eq!(Ports::AllExcept(vec![]).nft_rules("t"), "");
    }

    #[test]
    fn rejects_non_ipv4() {
        assert_eq!(policy().check(&[0x60; 40], Ipv4Addr::from(CLIENT)), Err(Denied::Malformed));
    }
}
