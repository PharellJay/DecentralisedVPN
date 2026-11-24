//! Reading routes, addresses and links straight from the kernel (rtnetlink), instead of
//! running `ip` and parsing its output. Reading needs no privileges. These are the
//! queries made over and over (the network watcher checks every few seconds); changes
//! to routes and the firewall, made a few times per connection, still go through
//! `ip` and `nft` ([`super::cmd`]).

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteType};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

/// A route as the kernel reports it, IPv4 only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    /// Outgoing interface index.
    pub oif: Option<u32>,
    pub table: u32,
    pub kind: RouteType,
    /// The metric; lower wins.
    pub priority: u32,
}

/// Sends `message` and collects the answers: every part of a dump, or the one reply.
fn request(message: RouteNetlinkMessage, dump: bool) -> io::Result<Vec<RouteNetlinkMessage>> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | if dump { NLM_F_DUMP } else { 0 };
    header.sequence_number = 1;
    let mut packet = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(message));
    packet.finalize();
    let mut buf = vec![0u8; packet.buffer_len()];
    packet.serialize(&mut buf);
    socket.send(&buf, 0)?;

    let mut answers = Vec::new();
    loop {
        let (datagram, _) = socket.recv_from_full()?;
        let mut offset = 0;
        while offset < datagram.len() {
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&datagram[offset..])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let length = message.header.length as usize;
            if length == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "empty netlink message"));
            }
            offset += length.next_multiple_of(4);
            match message.payload {
                NetlinkPayload::InnerMessage(inner) => {
                    answers.push(inner);
                    if !dump {
                        return Ok(answers);
                    }
                }
                NetlinkPayload::Done(_) => return Ok(answers),
                NetlinkPayload::Error(error) => {
                    return match error.code {
                        Some(code) => Err(io::Error::from_raw_os_error(-code.get())),
                        None => Ok(answers), // an acknowledgement
                    };
                }
                NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => {}
                _ => {}
            }
        }
    }
}

fn route_of(message: RouteMessage) -> Option<Route> {
    if message.header.address_family != AddressFamily::Inet {
        return None;
    }
    let mut route = Route {
        destination: Ipv4Addr::UNSPECIFIED,
        prefix_len: message.header.destination_prefix_length,
        gateway: None,
        oif: None,
        table: u32::from(message.header.table),
        kind: message.header.kind,
        priority: 0,
    };
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(ip)) => route.destination = ip,
            RouteAttribute::Gateway(RouteAddress::Inet(ip)) => route.gateway = Some(ip),
            RouteAttribute::Oif(index) => route.oif = Some(index),
            RouteAttribute::Table(table) => route.table = table,
            RouteAttribute::Priority(priority) => route.priority = priority,
            _ => {}
        }
    }
    Some(route)
}

/// Every IPv4 route in every table.
pub fn routes() -> io::Result<Vec<Route>> {
    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet;
    Ok(request(RouteNetlinkMessage::GetRoute(message), true)?
        .into_iter()
        .filter_map(|m| match m {
            RouteNetlinkMessage::NewRoute(route) => route_of(route),
            _ => None,
        })
        .collect())
}

/// The route the kernel would use to reach `ip` now (`ip route get`).
pub fn route_to(ip: Ipv4Addr) -> io::Result<Option<Route>> {
    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet;
    message.header.destination_prefix_length = 32;
    message.attributes.push(RouteAttribute::Destination(RouteAddress::Inet(ip)));
    match request(RouteNetlinkMessage::GetRoute(message), false) {
        Ok(answers) => Ok(answers.into_iter().find_map(|m| match m {
            RouteNetlinkMessage::NewRoute(route) => route_of(route),
            _ => None,
        })),
        // No route at all (ENETUNREACH), like `ip route get` failing.
        Err(e) if e.raw_os_error() == Some(101) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The main table's default route with the lowest metric (`ip route show default`).
pub fn default_route() -> io::Result<Option<Route>> {
    Ok(routes()?
        .into_iter()
        .filter(|r| r.prefix_len == 0 && r.table == u32::from(RouteHeader::RT_TABLE_MAIN) && r.kind == RouteType::Unicast)
        .min_by_key(|r| r.priority))
}

/// The name of the interface with `index`.
pub fn interface_name(index: u32) -> io::Result<Option<String>> {
    let mut message = LinkMessage::default();
    message.header.index = index;
    Ok(request(RouteNetlinkMessage::GetLink(message), false)?.into_iter().find_map(|m| match m {
        RouteNetlinkMessage::NewLink(link) => link.attributes.into_iter().find_map(|a| match a {
            LinkAttribute::IfName(name) => Some(name),
            _ => None,
        }),
        _ => None,
    }))
}

/// This host's IPv4 addresses with their prefix lengths (`ip -4 addr`).
pub fn ipv4_addresses() -> io::Result<Vec<(Ipv4Addr, u8)>> {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    Ok(request(RouteNetlinkMessage::GetAddress(message), true)?
        .into_iter()
        .filter_map(|m| match m {
            RouteNetlinkMessage::NewAddress(address) if address.header.family == AddressFamily::Inet => {
                // The local address; on point-to-point links IFA_ADDRESS is the peer's.
                let mut local = None;
                let mut peer = None;
                for attribute in &address.attributes {
                    match attribute {
                        AddressAttribute::Local(IpAddr::V4(ip)) => local = Some(*ip),
                        AddressAttribute::Address(IpAddr::V4(ip)) => peer = Some(*ip),
                        _ => {}
                    }
                }
                local.or(peer).map(|ip| (ip, address.header.prefix_len))
            }
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compared with what `ip` reports on this machine, where it's installed.
    #[test]
    fn reads_the_same_as_iproute2() {
        let Ok(out) = std::process::Command::new("ip").args(["-o", "-4", "addr", "show"]).output() else {
            return;
        };
        let from_ip = super::super::net::parse_ipv4_networks(&String::from_utf8_lossy(&out.stdout));
        let mut from_netlink: Vec<String> =
            ipv4_addresses().unwrap().iter().map(|(ip, len)| format!("{ip}/{len}")).collect();
        let mut from_ip: Vec<String> = from_ip.iter().map(ToString::to_string).collect();
        from_netlink.sort();
        from_ip.sort();
        assert_eq!(from_netlink, from_ip);
        assert!(from_netlink.contains(&"127.0.0.1/8".to_string()));

        // Loopback is always reachable, through lo.
        let route = route_to(Ipv4Addr::LOCALHOST).unwrap().expect("a route to loopback");
        assert_eq!(interface_name(route.oif.unwrap()).unwrap().as_deref(), Some("lo"));
    }
}
