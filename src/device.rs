//! Packet devices: the real TUN interface, behind a trait so forwarding logic can be
//! tested without root.

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;

pub trait PacketDevice: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

/// A Linux TUN device (needs root / CAP_NET_ADMIN). Removed when dropped.
pub struct TunDevice(tun_rs::AsyncDevice);

impl TunDevice {
    pub fn create(name: &str, addr: Ipv4Addr, prefix: u8, mtu: u16) -> io::Result<Self> {
        let device = tun_rs::DeviceBuilder::new()
            .name(name)
            .ipv4(addr, prefix, None)
            .mtu(mtu)
            .build_async()
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(e.kind(), "creating a TUN device needs root (CAP_NET_ADMIN)")
                } else {
                    e
                }
            })?;
        Ok(Self(device))
    }

    /// Swaps the device's IPv4 address without ever leaving it with none: Linux deletes
    /// every route through a device that loses its last IPv4 address, which would
    /// silently remove the client's kill-switch routes.
    pub fn replace_address(&self, old: Ipv4Addr, new: Ipv4Addr, prefix: u8) -> io::Result<()> {
        self.0.add_address_v4(new, prefix)?;
        self.0.remove_address(old.into())
    }
}

impl PacketDevice for TunDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }

    async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.0.send(packet).await
    }
}
