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

    /// Like [`Self::create`], with `queues` queues (Linux multi-queue TUN): the kernel
    /// spreads received packets over them by flow, so several tasks can read at once.
    /// Falls back to one queue where multi-queue isn't available.
    pub fn create_queues(name: &str, addr: Ipv4Addr, prefix: u8, mtu: u16, queues: usize) -> io::Result<Vec<Self>> {
        if queues <= 1 {
            return Ok(vec![Self::create(name, addr, prefix, mtu)?]);
        }
        let first = tun_rs::DeviceBuilder::new()
            .name(name)
            .ipv4(addr, prefix, None)
            .mtu(mtu)
            .with(|builder| {
                builder.multi_queue(true);
            })
            .build_async();
        let first = match first {
            Ok(device) => device,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Self::create(name, addr, prefix, mtu).map(|d| vec![d]),
            Err(e) => {
                tracing::warn!("no multi-queue TUN ({e}); using one queue");
                return Ok(vec![Self::create(name, addr, prefix, mtu)?]);
            }
        };
        let mut devices = Vec::with_capacity(queues);
        for _ in 1..queues {
            match first.try_clone() {
                Ok(queue) => devices.push(Self(queue)),
                Err(e) => {
                    tracing::warn!("could not add a TUN queue ({e}); using {}", devices.len() + 1);
                    break;
                }
            }
        }
        devices.insert(0, Self(first));
        Ok(devices)
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
