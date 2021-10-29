use crate::phy::{Eth, Slip};
use embedded_hal::serial::{Read, Write};
use smoltcp::iface::{EthernetInterface, EthernetInterfaceBuilder, NeighborCache, Routes};
use smoltcp::socket::SocketSet;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Cidr};
use std::collections::BTreeMap;

/// SLIP interface
pub struct Interface<'a, T>
where
    T: 'static + Read<u8> + Write<u8>,
{
    local_addr: Ipv4Address,
    peer_addr: Ipv4Address,
    iface: EthernetInterface<'a, Eth<Slip<T>>>,
}

impl<'a, T> Interface<'a, T>
where
    T: Read<u8> + Write<u8>,
{
    /// Create a new SLIP interface.
    ///
    /// The `device` should be able to send and receive bytes from a serial port.
    /// `local_addr` and `peer_addr` are used to setup the point-to-point interface.
    pub fn new<L, P>(device: T, local_addr: L, peer_addr: P) -> Self
    where
        L: Into<Ipv4Cidr>,
        P: Into<Ipv4Address>,
    {
        let device = Eth::from(Slip::from(device));
        let local_addr = local_addr.into();
        let peer_addr = peer_addr.into();
        let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(EthernetAddress([0; 6]))
            .ip_addrs([local_addr.into()])
            .neighbor_cache(NeighborCache::new(BTreeMap::new()))
            .routes(Routes::new(BTreeMap::new()))
            .finalize();
        let local_addr = local_addr.address();
        iface.routes_mut().add_default_ipv4_route(local_addr).ok();
        Self {
            local_addr,
            peer_addr,
            iface,
        }
    }

    /// Get a reference to the inner serial device.
    pub fn device(&self) -> &T {
        self.iface.device().as_ref().as_ref()
    }

    /// Get a mutable reference to the inner serial device.
    pub fn device_mut(&mut self) -> &mut T {
        self.iface.device_mut().as_mut().as_mut()
    }

    /// Get the IPv4 address of the local device.
    pub fn local_addr(&self) -> Ipv4Address {
        self.local_addr
    }

    /// Get the IPv4 address of the remove device.
    pub fn peer_addr(&self) -> Ipv4Address {
        self.peer_addr
    }

    /// Transmit packets queued in the given sockets, and receive packets queued in the device.
    ///
    /// See [`EthernetInterface::poll`] for more information.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> smoltcp::Result<bool> {
        self.iface.poll(sockets, timestamp)
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    ///
    /// See [`EthernetInterface::poll_at`] for more information.
    ///
    /// [poll]: Self::poll
    pub fn poll_at(&self, sockets: &mut SocketSet, timestamp: Instant) -> Option<Instant> {
        self.iface.poll_at(sockets, timestamp)
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    ///
    /// See [`EthernetInterface::poll_delay`] for more information.
    ///
    /// [poll]: Self::poll
    pub fn poll_delay(&self, sockets: &mut SocketSet, timestamp: Instant) -> Option<Duration> {
        self.iface.poll_delay(sockets, timestamp)
    }
}

impl<'a, T> From<Interface<'a, T>> for EthernetInterface<'a, Eth<Slip<T>>>
where
    T: Read<u8> + Write<u8>,
{
    fn from(iface: Interface<'a, T>) -> Self {
        iface.iface
    }
}

#[cfg(test)]
mod tests {
    use super::Interface;
    use embedded_hal_mock::serial::{Mock, Transaction};
    use log::info;
    use simple_logger::SimpleLogger;
    use slip_codec::encode;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::socket::{IcmpEndpoint, IcmpSocket, IcmpSocketBuffer, SocketSet};
    use smoltcp::storage::PacketMetadata;
    use smoltcp::time::{Duration, Instant};
    use smoltcp::wire::{
        Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet, Ipv4Repr,
    };
    use smoltcp::Result;

    #[allow(clippy::too_many_lines)]
    #[test]
    fn ping() -> Result<()> {
        SimpleLogger::new().init().ok();

        // create a fake SLIP device
        let device = Mock::new(&[]);

        // create a SLIP interface
        let mut iface = Interface::new(
            device,
            Ipv4Cidr::new(Ipv4Address([192, 168, 1, 1]), 24),
            Ipv4Address([192, 168, 1, 2]),
        );

        // create a socket registry
        let mut sockets = [None; 1];
        let mut sockets = SocketSet::new(&mut sockets[..]);

        // create a socket
        let rx_metadata_storage = [PacketMetadata::EMPTY; 1];
        let rx_payload_storage = [0; 18];
        let rx_buffer = IcmpSocketBuffer::new(rx_metadata_storage, rx_payload_storage);
        let tx_metadata_storage = [PacketMetadata::EMPTY; 1];
        let tx_payload_storage = [0; 18];
        let tx_buffer = IcmpSocketBuffer::new(tx_metadata_storage, tx_payload_storage);
        let socket = IcmpSocket::new(rx_buffer, tx_buffer);
        let handle = sockets.add(socket);

        {
            info!("bind socket");
            let mut socket = sockets.get::<IcmpSocket>(handle);
            socket.bind(IcmpEndpoint::Ident(1)).unwrap();

            info!("send ping");
            let icmp_repr = Icmpv4Repr::EchoRequest {
                ident: 1,
                seq_no: 1,
                data: b"0123456789",
            };
            let ip_repr = Ipv4Repr {
                src_addr: iface.local_addr(),
                dst_addr: iface.peer_addr(),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            let ip_buf = vec![0; ip_repr.buffer_len() + icmp_repr.buffer_len()];
            let mut ip_packet = Ipv4Packet::new_checked(ip_buf)?;
            let caps = ChecksumCapabilities::default();
            ip_repr.emit(&mut ip_packet, &caps);

            let mut icmp_packet = Icmpv4Packet::new_checked(ip_packet.payload_mut())?;
            icmp_repr.emit(&mut icmp_packet, &caps);
            socket.send_slice(icmp_packet.into_inner(), iface.peer_addr().into())?;

            // Check transmitted SLIP frame
            let ip_buf = ip_packet.into_inner();
            let mut slip_buf = Vec::with_capacity(ip_buf.len() * 2 + 2);
            encode(&ip_buf, &mut slip_buf).unwrap();
            iface.device_mut().expect(&[
                Transaction::read_error(nb::Error::WouldBlock),
                Transaction::read_error(nb::Error::WouldBlock),
                Transaction::write_many(slip_buf),
                Transaction::read_error(nb::Error::WouldBlock),
            ]);
        }

        let timestamp = Instant::from_millis(0);
        assert!(!iface.poll(&mut sockets, timestamp)?);
        assert_eq!(
            iface.poll_delay(&mut sockets, timestamp),
            Some(Duration::from_secs(3))
        );
        assert!(iface.poll(&mut sockets, timestamp)?);
        assert_eq!(iface.poll_delay(&mut sockets, timestamp), None);
        iface.device_mut().done();

        // Send response
        {
            let icmp_repr = Icmpv4Repr::EchoReply {
                ident: 1,
                seq_no: 1,
                data: b"0123456789",
            };
            let ip_repr = Ipv4Repr {
                src_addr: iface.peer_addr(),
                dst_addr: iface.local_addr(),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            let mut buf = vec![0; ip_repr.buffer_len() + icmp_repr.buffer_len()];
            let mut ip_packet = Ipv4Packet::new_checked(&mut buf)?;
            let caps = ChecksumCapabilities::default();
            ip_repr.emit(&mut ip_packet, &caps);

            let mut imcp_packet = Icmpv4Packet::new_checked(ip_packet.payload_mut())?;
            icmp_repr.emit(&mut imcp_packet, &caps);

            let mut slip_buf = Vec::with_capacity(buf.len() * 2 + 2);
            encode(&buf, &mut slip_buf).unwrap();
            iface.device_mut().expect(&[
                Transaction::read_many(slip_buf),
                Transaction::read_error(nb::Error::WouldBlock),
                Transaction::read_error(nb::Error::WouldBlock),
            ]);
        }

        assert!(iface.poll(&mut sockets, Instant::from_millis(0))?);
        assert_eq!(
            iface.poll_delay(&mut sockets, Instant::from_millis(0)),
            None
        );
        iface.device_mut().done();

        {
            info!("receive pong");
            let mut socket = sockets.get::<IcmpSocket>(handle);
            let (buf, addr) = socket.recv()?;
            assert_eq!(addr, iface.peer_addr().into());
            let packet = Icmpv4Packet::new_checked(buf)?;
            let repr = Icmpv4Repr::parse(&packet, &ChecksumCapabilities::default())?;
            assert!(matches!(
                repr,
                Icmpv4Repr::EchoReply {
                    ident: 1,
                    seq_no: 1,
                    data: b"0123456789"
                }
            ));
        }

        Ok(())
    }
}
