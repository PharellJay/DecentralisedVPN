//! Everything that depends on the operating system, behind one interface. The rest of
//! dvpn (node, circuits, exit forwarding and policy, controller, the app's protocol) is
//! the same on every platform and reaches the system only through this module.
//!
//! Only Linux is implemented. A port provides the same modules and items:
//!
//! | Module | Provides | Linux | Windows (planned) |
//! |---|---|---|---|
//! | [`tunnel`] | `RouteGuard`: all IPv4 into the TUN device, relays exempted, DNS pinned to the tunnel. `KillSwitch`: nothing leaves except through the tunnel, to the LAN or from dvpn itself; recovery after a crash | iproute2, systemd-resolved, nftables matching dvpn's cgroup | IP Helper routes, NRPT, WFP filters matching dvpn's app ID |
//! | [`exit`] | `ExitNetwork`: forwarding, NAT and a firewall confining lent traffic, routing that keeps it out of our own tunnel; `deny_destination`; recovery | `ip_forward`, nftables, policy routing | WinNAT, WFP |
//! | [`files`] | files and directories only their owner can read (keys, settings) | modes `0600`/`0700` | ACLs |
//! | [`net`] | the default route (`NextHop`), the networks this host is attached to | netlink (rtnetlink) | IP Helper |
//! | [`ipc`] | the control socket (`Listener`, `Stream`), who is on the other end (`Peer`) | Unix socket, `SO_PEERCRED` | named pipe, client token |
//! | [`service`] | where the service keeps its socket and data, socket activation, shutdown signals, `Access`: who may control it | systemd, polkit, `/etc/group` | service control manager, local groups |
//!
//! Plus `valid_interface_name` and `other_dvpn_in_this_namespace`. The TUN device itself
//! ([`crate::device`]) uses tun-rs, which also supports Windows (Wintun) and macOS.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
compile_error!("dvpn runs on Linux only so far; src/platform/mod.rs lists what a port provides");
