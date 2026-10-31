//! Client routing while connected: all IPv4 through the TUN device, the entry relay(s)
//! via the original route, IPv6 blackholed, and DNS pinned to the tunnel.
//!
//! Everything is undone when the [`RouteGuard`] drops. While it exists the routes stay
//! in place even if the circuit fails, so traffic is dropped rather than leaked
//! (kill switch).

use std::collections::HashSet;
use std::net::Ipv4Addr;

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::system::{self, NextHop};

pub struct RouteGuard {
    dev: String,
    /// The pre-VPN default route, used for relay exemptions.
    original_default: Option<NextHop>,
    exempted: HashSet<Ipv4Addr>,
    /// Commands that undo what we installed, applied in reverse order.
    undo: Vec<(&'static str, Vec<String>)>,
}

impl RouteGuard {
    /// Routes all IPv4 traffic into `dev` and blackholes IPv6. With `dns`, the
    /// tunnel's DNS server is set via systemd-resolved.
    pub fn install(dev: &str, dns: Option<Ipv4Addr>) -> anyhow::Result<Self> {
        let mut guard = Self {
            dev: dev.to_string(),
            original_default: system::default_route()?,
            exempted: HashSet::new(),
            undo: Vec::new(),
        };
        // Two /1 routes override the default route without replacing it.
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            guard.apply("ip", &["-4", "route", "add", half, "dev", dev], &["-4", "route", "del", half, "dev", dev])?;
        }
        for half in ["::/1", "8000::/1"] {
            if let Err(e) = guard.apply(
                "ip",
                &["-6", "route", "add", "blackhole", half],
                &["-6", "route", "del", "blackhole", half],
            ) {
                warn!("could not block IPv6 ({e:#}); IPv6 traffic may bypass the tunnel");
            }
        }
        if let Some(dns) = dns {
            let dns = dns.to_string();
            let configured = system::run("resolvectl", &["dns", dev, &dns])
                .and_then(|_| system::run("resolvectl", &["domain", dev, "~."]));
            match configured {
                Ok(_) => {
                    guard.undo.push(("resolvectl", vec!["revert".into(), dev.into()]));
                    info!("DNS goes through the tunnel");
                }
                Err(e) => warn!("could not configure DNS ({e:#}); DNS queries may leak outside the tunnel"),
            }
        }
        Ok(guard)
    }

    /// Keeps `ip` (an entry relay) on its original route, so the tunnel's own
    /// traffic doesn't loop into the tunnel.
    pub fn exempt(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        if !self.exempted.insert(ip) {
            return Ok(());
        }
        let current = system::route_get(ip)?;
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
        system::run(program, args)?;
        self.undo.push((program, undo.iter().map(|s| s.to_string()).collect()));
        Ok(())
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for (program, args) in self.undo.drain(..).rev() {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(e) = system::run(program, &args) {
                warn!("cleanup step failed: {e:#}");
            }
        }
        info!("routes restored");
    }
}
