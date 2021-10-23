use crate::phy::{Eth, Slip};
use smoltcp::iface::{EthernetInterface, EthernetInterfaceBuilder, NeighborCache, Routes};
use smoltcp::phy::Device;
use smoltcp::socket::SocketSet;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Cidr};
use std::collections::BTreeMap;

/// SLIP interface
pub struct Interface<'a, T>
where
    T: for<'d> Device<'d>,
{
    local_addr: Ipv4Address,
    peer_addr: Ipv4Address,
    iface: EthernetInterface<'a, Eth<Slip<T>>>,
}

impl<'a, T> Interface<'a, T>
where
    T: for<'d> Device<'d>,
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

#[cfg(test)]
mod tests {
    use super::Interface;
    use crate::tests::Mock;
    use log::info;
    use simple_logger::SimpleLogger;
    use slip_codec::{encode, Decoder};
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
        let device = Mock::default();

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
            let repr = Icmpv4Repr::EchoRequest {
                ident: 1,
                seq_no: 1,
                data: b"0123456789",
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = Icmpv4Packet::new_checked(&mut buffer)?;
            repr.emit(&mut packet, &ChecksumCapabilities::default());
            socket.send_slice(packet.into_inner(), iface.peer_addr().into())?;
        }

        let timestamp = Instant::from_millis(0);
        assert!(!iface.poll(&mut sockets, timestamp)?);
        assert_eq!(
            iface.poll_delay(&mut sockets, timestamp),
            Some(Duration::from_secs(3))
        );
        assert!(iface.poll(&mut sockets, timestamp)?);
        assert_eq!(iface.poll_delay(&mut sockets, timestamp), None);
        assert_eq!(iface.device().rx, Vec::new());

        // Check transmitted packet
        {
            let tx = &mut iface.device_mut().tx;
            let mut decoder = Decoder::new();
            let mut ip_buf = Vec::new();
            decoder.decode(&mut &tx[..], &mut ip_buf).unwrap();
            *tx = Vec::new();
            let packet = Ipv4Packet::new_checked(&ip_buf)?;
            let repr = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default())?;
            assert_eq!(repr.src_addr, iface.local_addr());
            assert_eq!(repr.dst_addr, iface.peer_addr());
            assert_eq!(repr.protocol, IpProtocol::Icmp);
            assert_eq!(repr.hop_limit, 64);
            let packet = Icmpv4Packet::new_checked(packet.payload())?;
            let repr = Icmpv4Repr::parse(&packet, &ChecksumCapabilities::default())?;
            if let Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } = repr
            {
                assert_eq!(ident, 1);
                assert_eq!(seq_no, 1);
                assert_eq!(data, b"0123456789");
            } else {
                panic!();
            }
        }

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
            let mut packet = Ipv4Packet::new_checked(&mut buf)?;
            let caps = ChecksumCapabilities::default();
            ip_repr.emit(&mut packet, &caps);
            {
                let mut packet = Icmpv4Packet::new_checked(packet.payload_mut())?;
                icmp_repr.emit(&mut packet, &caps);
            }
            let mut rx = &mut iface.device_mut().rx;
            encode(packet.into_inner(), &mut rx).unwrap();
        }

        assert!(iface.poll(&mut sockets, Instant::from_millis(0))?);
        assert_eq!(
            iface.poll_delay(&mut sockets, Instant::from_millis(0)),
            None
        );

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
