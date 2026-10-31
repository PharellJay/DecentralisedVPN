//! Minimal IPv4 header parsing for exit policy checks and session routing.

use std::net::Ipv4Addr;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    /// Set for any fragment except an unfragmented packet.
    pub fragmented: bool,
    /// Destination port of an unfragmented or first-fragment TCP/UDP packet.
    pub dst_port: Option<u16>,
}

/// Parses an IPv4 header; `None` for anything that isn't a well-formed IPv4 packet.
pub fn parse(packet: &[u8]) -> Option<Ipv4Info> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if header_len < 20 || total_len < header_len || total_len > packet.len() {
        return None;
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = flags_offset & 0x2000 != 0;
    let offset = flags_offset & 0x1fff;
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let dst_port = match protocol {
        PROTO_TCP | PROTO_UDP if offset == 0 && total_len >= header_len + 4 => {
            Some(u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]))
        }
        _ => None,
    };
    Some(Ipv4Info {
        src,
        dst,
        protocol,
        fragmented: more_fragments || offset != 0,
        dst_port,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a minimal IPv4 packet with a 4-byte TCP/UDP port header.
    pub(crate) fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[6] = 0x40; // don't fragment
        p[8] = 64;
        p[9] = protocol;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&40000u16.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn parses_tcp_header() {
        let info = parse(&ipv4([10, 77, 0, 2], [93, 184, 216, 34], PROTO_TCP, 443)).unwrap();
        assert_eq!(info.src, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(info.dst, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(info.dst_port, Some(443));
        assert!(!info.fragmented);
    }

    #[test]
    fn rejects_garbage_and_ipv6() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x60; 40]).is_none());
        let mut truncated = ipv4([1, 1, 1, 1], [2, 2, 2, 2], PROTO_UDP, 53);
        truncated[2..4].copy_from_slice(&500u16.to_be_bytes());
        assert!(parse(&truncated).is_none());
    }

    #[test]
    fn later_fragments_have_no_port() {
        let mut p = ipv4([1, 1, 1, 1], [2, 2, 2, 2], PROTO_TCP, 25);
        p[6..8].copy_from_slice(&0x0010u16.to_be_bytes()); // offset 16, no flags
        let info = parse(&p).unwrap();
        assert!(info.fragmented);
        assert_eq!(info.dst_port, None);
    }
}
