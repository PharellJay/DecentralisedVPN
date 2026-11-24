//! DNS through the tunnel, the part every platform shares.

use std::net::Ipv4Addr;

/// DNS-over-TLS through the tunnel, so the exit can't read queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsOverTls {
    /// Only encrypted DNS; if the server doesn't support it, names don't resolve.
    Yes,
    /// Encrypted when the server supports it; an exit can force plain DNS.
    Opportunistic,
    No,
}

impl std::str::FromStr for DnsOverTls {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "yes" => Ok(Self::Yes),
            "opportunistic" => Ok(Self::Opportunistic),
            "no" => Ok(Self::No),
            _ => Err(format!("expected yes, opportunistic or no, got {s}")),
        }
    }
}

/// The TLS name of well-known public resolvers, so the system resolver can check the
/// server's certificate, not just encrypt to whoever answers.
pub fn tls_name(dns: Ipv4Addr) -> Option<&'static str> {
    match dns.octets() {
        [9, 9, 9, 9] | [149, 112, 112, 112] => Some("dns.quad9.net"),
        [1, 1, 1, 1] | [1, 0, 0, 1] => Some("cloudflare-dns.com"),
        [8, 8, 8, 8] | [8, 8, 4, 4] => Some("dns.google"),
        _ => None,
    }
}
