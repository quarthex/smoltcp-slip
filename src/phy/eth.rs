use log::error;
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, Ipv4Address, ETHERNET_HEADER_LEN,
};
use smoltcp::{Error, Result};

pub struct ArpReq {
    source: Ipv4Address,
    target: Ipv4Address,
}

pub struct Eth<T> {
    inner: T,
    arp: Option<ArpReq>,
}

impl<'a, T> Device<'a> for Eth<T>
where
    T: Device<'a>,
{
    type RxToken = EthRxToken<T::RxToken>;
    type TxToken = EthTxToken<'a, T::TxToken>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let Self { inner, arp } = self;
        if let Some(req) = arp.take() {
            let rx_token = Self::RxToken::Arp(req);
            let tx_token = Self::TxToken::Arp;
            Some((rx_token, tx_token))
        } else if let Some((rx_token, tx_token)) = inner.receive() {
            let rx_token = Self::RxToken::Token(rx_token);
            let tx_token = Self::TxToken::Token {
                token: tx_token,
                arp,
            };
            Some((rx_token, tx_token))
        } else {
            None
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let Self { inner, arp } = self;
        if let Some(token) = inner.transmit() {
            Some(Self::TxToken::Token { token, arp })
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = self.inner.capabilities();
        capabilities.max_transmission_unit += ETHERNET_HEADER_LEN;
        capabilities
    }
}

const LOCAL_ADDR: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 0]);
const PEER_ADDR: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 1]);

pub enum EthRxToken<T> {
    Token(T),
    Arp(ArpReq),
}

impl<T> RxToken for EthRxToken<T>
where
    T: RxToken,
{
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        match self {
            Self::Token(token) => token.consume(timestamp, |buf| {
                let repr = EthernetRepr {
                    src_addr: PEER_ADDR,
                    dst_addr: LOCAL_ADDR,
                    ethertype: EthernetProtocol::Ipv4,
                };
                let mut vec = vec![0; repr.buffer_len() + buf.len()];
                let mut frame = EthernetFrame::new_checked(&mut vec)?;
                repr.emit(&mut frame);
                frame.payload_mut().copy_from_slice(buf);
                f(frame.into_inner())
            }),
            Self::Arp(ArpReq { source, target }) => {
                let eth_repr = EthernetRepr {
                    src_addr: PEER_ADDR,
                    dst_addr: LOCAL_ADDR,
                    ethertype: EthernetProtocol::Arp,
                };
                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: PEER_ADDR,
                    source_protocol_addr: target,
                    target_hardware_addr: LOCAL_ADDR,
                    target_protocol_addr: source,
                };
                let mut buf = vec![0; eth_repr.buffer_len() + arp_repr.buffer_len()];
                let mut eth_frame = EthernetFrame::new_checked(&mut buf)?;
                eth_repr.emit(&mut eth_frame);
                let mut arp_packet = ArpPacket::new_checked(eth_frame.payload_mut())?;
                arp_repr.emit(&mut arp_packet);
                f(eth_frame.into_inner())
            }
        }
    }
}

pub enum EthTxToken<'a, T> {
    Token {
        token: T,
        arp: &'a mut Option<ArpReq>,
    },
    Arp,
}

impl<T> TxToken for EthTxToken<'_, T>
where
    T: TxToken,
{
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        match self {
            Self::Token { token, arp } => {
                let mut buf = vec![0; len];
                let res = f(&mut buf)?;
                let frame = EthernetFrame::new_checked(&buf)?;
                let repr = EthernetRepr::parse(&frame)?;
                match repr.ethertype {
                    EthernetProtocol::Ipv4 => {
                        token.consume(timestamp, frame.payload().len(), |buf| {
                            buf.copy_from_slice(frame.payload());
                            Ok(res)
                        })
                    }
                    EthernetProtocol::Arp => {
                        debug_assert!(repr.src_addr == LOCAL_ADDR);
                        debug_assert!(repr.dst_addr.is_broadcast());
                        let packet = ArpPacket::new_checked(frame.payload())?;
                        let repr = ArpRepr::parse(&packet)?;
                        debug_assert!(matches!(
                            repr,
                            ArpRepr::EthernetIpv4 {
                                operation: ArpOperation::Request,
                                source_hardware_addr: LOCAL_ADDR,
                                target_hardware_addr: EthernetAddress::BROADCAST,
                                ..
                            }
                        ));
                        if let ArpRepr::EthernetIpv4 {
                            source_protocol_addr: source,
                            target_protocol_addr: target,
                            ..
                        } = repr
                        {
                            *arp = Some(ArpReq { source, target });
                            Ok(res)
                        } else {
                            Err(Error::Dropped)
                        }
                    }
                    EthernetProtocol::Ipv6 | EthernetProtocol::Unknown(..) => {
                        error!("Unexpected protocol {}", repr.ethertype);
                        Err(Error::Dropped)
                    }
                }
            }
            Self::Arp => unimplemented!(),
        }
    }
}

impl<T> From<T> for Eth<T> {
    fn from(inner: T) -> Self {
        Self { inner, arp: None }
    }
}

impl<T> AsRef<T> for Eth<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for Eth<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::{Eth, LOCAL_ADDR, PEER_ADDR};
    use embedded_hal::serial::{Read, Write};
    use embedded_hal_mock::serial::{Mock, Transaction};
    use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, RxToken, TxToken};
    use smoltcp::time::Instant;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
        EthernetRepr, Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
    };
    use std::sync::{Arc, Mutex};

    struct MockDevice(Arc<Mutex<Mock<u8>>>);

    impl MockDevice {
        fn done(&self) {
            self.0.lock().unwrap().done()
        }
    }

    impl From<Mock<u8>> for MockDevice {
        fn from(mock: Mock<u8>) -> Self {
            Self(Arc::new(Mutex::new(mock)))
        }
    }

    impl<'a> Device<'a> for MockDevice {
        type RxToken = Self;
        type TxToken = Self;

        fn receive(&'a mut self) -> std::option::Option<(Self::RxToken, Self::TxToken)> {
            let rx = Self(self.0.clone());
            let tx = Self(self.0.clone());
            Some((rx, tx))
        }

        fn transmit(&'a mut self) -> std::option::Option<Self::TxToken> {
            Some(Self(self.0.clone()))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            DeviceCapabilities::default()
        }
    }

    impl RxToken for MockDevice {
        fn consume<R, F>(self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
        where
            F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
        {
            let mut buf = Vec::new();
            loop {
                match self.0.lock().unwrap().read() {
                    Ok(b) => buf.push(b),
                    Err(nb::Error::Other(err)) => panic!("{}", err),
                    Err(nb::Error::WouldBlock) => return f(&mut buf),
                }
            }
        }
    }

    impl TxToken for MockDevice {
        fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
        where
            F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
        {
            let mut buf = vec![0; len];
            let res = f(&mut buf);
            for b in buf.into_iter() {
                self.0.lock().unwrap().write(b).unwrap()
            }
            res
        }
    }

    fn ipv4_frame() -> Vec<u8> {
        let caps = ChecksumCapabilities::default();
        let icmp_repr = Icmpv4Repr::EchoRequest {
            ident: 0,
            seq_no: 0,
            data: b"HELO",
        };
        let ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 0, 1),
            dst_addr: Ipv4Address::new(192, 168, 0, 2),
            protocol: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 0,
        };
        let mut buf = vec![0; ip_repr.buffer_len() + icmp_repr.buffer_len()];
        ip_repr.emit(&mut Ipv4Packet::new_checked(&mut buf).unwrap(), &caps);
        icmp_repr.emit(
            &mut Icmpv4Packet::new_checked(&mut buf[ip_repr.buffer_len()..]).unwrap(),
            &caps,
        );
        buf
    }

    fn eth_frame() -> Vec<u8> {
        let ipv4_frame = ipv4_frame();
        let eth_repr = EthernetRepr {
            src_addr: PEER_ADDR,
            dst_addr: LOCAL_ADDR,
            ethertype: EthernetProtocol::Ipv4,
        };
        let mut buf = vec![0; eth_repr.buffer_len() + ipv4_frame.len()];
        eth_repr.emit(&mut EthernetFrame::new_checked(&mut buf).unwrap());
        buf[eth_repr.buffer_len()..].copy_from_slice(&ipv4_frame);
        buf
    }

    #[test]
    fn rx() {
        let mock = Mock::new(&[
            Transaction::read_many(ipv4_frame()),
            Transaction::read_error(nb::Error::WouldBlock),
        ]);
        let mut eth = Eth::from(MockDevice::from(mock));
        let (rx, _tx) = eth.receive().unwrap();
        rx.consume(Instant::from_millis(0), |_| Ok(())).unwrap();
        eth.as_ref().done();
    }

    #[test]
    fn tx() {
        let mock = Mock::new(&[Transaction::write_many(ipv4_frame())]);
        let mut eth = Eth::from(MockDevice::from(mock));
        let tx = eth.transmit().unwrap();
        let eth_frame = eth_frame();
        tx.consume(Instant::from_millis(0), eth_frame.len(), |buf| {
            buf.copy_from_slice(&eth_frame);
            Ok(())
        })
        .unwrap();
        eth.as_ref().done();
    }

    #[test]
    fn arp() {
        let mut eth = Eth::from(MockDevice::from(Mock::new(&[])));

        let tx = eth.transmit().unwrap();
        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: LOCAL_ADDR,
            source_protocol_addr: Ipv4Address::new(192, 168, 0, 1),
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: Ipv4Address::new(192, 168, 0, 2),
        };
        let eth_repr = EthernetRepr {
            src_addr: LOCAL_ADDR,
            dst_addr: EthernetAddress::BROADCAST,
            ethertype: EthernetProtocol::Arp,
        };

        tx.consume(
            Instant::from_millis(0),
            eth_repr.buffer_len() + repr.buffer_len(),
            |buf| {
                let mut packet = EthernetFrame::new_checked(buf)?;
                eth_repr.emit(&mut packet);
                let mut packet = ArpPacket::new_checked(packet.payload_mut())?;
                repr.emit(&mut packet);
                Ok(())
            },
        )
        .unwrap();

        let (rx, _tx) = eth.receive().unwrap();
        rx.consume(Instant::from_millis(0), |buf| {
            let frame = EthernetFrame::new_checked(&buf[..])?;
            let eth_repr = EthernetRepr::parse(&frame)?;
            assert_eq!(eth_repr.src_addr, PEER_ADDR);
            assert_eq!(eth_repr.dst_addr, LOCAL_ADDR);
            assert_eq!(eth_repr.ethertype, EthernetProtocol::Arp);
            let packet = ArpPacket::new_checked(frame.payload())?;
            let repr = ArpRepr::parse(&packet)?;
            assert_eq!(
                repr,
                ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: PEER_ADDR,
                    source_protocol_addr: Ipv4Address::new(192, 168, 0, 2),
                    target_hardware_addr: LOCAL_ADDR,
                    target_protocol_addr: Ipv4Address::new(192, 168, 0, 1),
                }
            );
            Ok(())
        })
        .unwrap();

        eth.as_ref().done();
    }
}
