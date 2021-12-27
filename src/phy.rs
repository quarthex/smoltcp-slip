use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::take;
use embedded_hal::serial::{Read, Write};
use log::error;
use serial_line_ip::{Decoder, Encoder};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::Result;

/// Encode an SLIP frame
pub fn encode(input: &[u8]) -> Vec<u8> {
    const END: u8 = 0xc0;
    const ESC: u8 = 0xdb;
    let size = 2 + input
        .iter()
        .map(|b| match *b {
            END | ESC => 2, // will be escaped
            _ => 1,
        })
        .sum::<usize>();
    let mut output = vec![0; size];
    let mut encoder = Encoder::new();
    if let Ok(totals) = encoder.encode(input, &mut output) {
        debug_assert!(totals.read == input.len());
        debug_assert!(totals.written == size - 1);
        if let Ok(totals) = encoder.finish(&mut output[totals.written..]) {
            debug_assert!(totals.read == 0);
            debug_assert!(totals.written == 1);
        }
    }
    output
}

/// SLIP device
pub struct SlipDevice<T> {
    serial: T,
    decoder: Decoder,
    tx: VecDeque<u8>,
    rx: Vec<u8>,
}

impl<T> SlipDevice<T>
where
    T: Write<u8>,
{
    fn drain(serial: &mut T, tx: &mut VecDeque<u8>) {
        while let Some(b) = tx.front().copied() {
            match serial.write(b) {
                Ok(()) => tx.pop_front(),
                Err(nb::Error::Other(..)) => {
                    error!("failed to send a frame");
                    tx.truncate(0);
                    break;
                }
                Err(nb::Error::WouldBlock) => break,
            };
        }
    }
}

impl<'a, T> Device<'a> for SlipDevice<T>
where
    T: 'a + Read<u8> + Write<u8>,
{
    type RxToken = SlipRxToken<'a>;
    type TxToken = SlipTxToken<'a, T>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        Self::drain(&mut self.serial, &mut self.tx);
        let mut output = [0];
        loop {
            use nb::Error;
            match self.serial.read() {
                Ok(b) => {
                    use serial_line_ip::Error;
                    match self.decoder.decode(&[b][..], &mut output) {
                        Ok((input_bytes_processed, output_slice, is_end_of_packet)) => {
                            debug_assert!(input_bytes_processed == 1);
                            if !output_slice.is_empty() {
                                debug_assert!(output_slice.len() == 1);
                                self.rx.push(output_slice[0]);
                            }
                            if is_end_of_packet {
                                let Self { serial, tx, rx, .. } = self;
                                let rx_token = Self::RxToken { rx };
                                let tx_token = Self::TxToken { serial, tx };
                                return Some((rx_token, tx_token));
                            }
                        }
                        Err(Error::NoOutputSpaceForHeader | Error::NoOutputSpaceForEndByte) => {
                            unreachable!("encode error");
                        }
                        Err(Error::BadHeaderDecode) => {
                            error!("bad header");
                            self.rx.truncate(0);
                        }
                        Err(Error::BadEscapeSequenceDecode) => {
                            error!("bad escape sequence");
                            self.rx.truncate(0);
                        }
                    }
                }
                Err(Error::Other(..)) => {
                    error!("failed to read from the serial port");
                    return None;
                }
                Err(Error::WouldBlock) => return None,
            }
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let Self { serial, tx, .. } = self;
        Self::drain(serial, tx);
        Some(Self::TxToken { serial, tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = (core::usize::MAX - 2) / 2;
        capabilities.medium = Medium::Ip;
        capabilities
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct SlipRxToken<'a> {
    rx: &'a mut Vec<u8>,
}

impl RxToken for SlipRxToken<'_> {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { rx } = self;
        f(&mut take(rx))
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct SlipTxToken<'a, T> {
    serial: &'a mut T,
    tx: &'a mut VecDeque<u8>,
}

impl<T> TxToken for SlipTxToken<'_, T>
where
    T: Write<u8>,
{
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { serial, tx } = self;
        let mut buf = vec![0; len];
        let res = f(&mut buf)?;
        tx.extend(encode(&buf));
        SlipDevice::drain(serial, tx);
        Ok(res)
    }
}

impl<T> From<T> for SlipDevice<T> {
    fn from(serial: T) -> Self {
        Self {
            serial,
            decoder: Decoder::new(),
            tx: VecDeque::new(),
            rx: Vec::new(),
        }
    }
}

impl<T> AsRef<T> for SlipDevice<T> {
    fn as_ref(&self) -> &T {
        &self.serial
    }
}

impl<T> AsMut<T> for SlipDevice<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::SlipDevice;
    use crate::phy::encode;
    use alloc::vec;
    use alloc::vec::Vec;
    use embedded_hal_mock::serial::{Mock, Transaction};
    use log::info;
    use simple_logger::SimpleLogger;
    use smoltcp::iface::InterfaceBuilder;
    use smoltcp::phy::{ChecksumCapabilities, Device, RxToken, TxToken};
    use smoltcp::socket::{IcmpEndpoint, IcmpSocket, IcmpSocketBuffer};
    use smoltcp::storage::PacketMetadata;
    use smoltcp::time::Instant;
    use smoltcp::wire::{
        Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet, Ipv4Repr,
    };
    use smoltcp::Result;

    const DECODED: [u8; 4] = *b"HELO";
    const ENCODED: [u8; 6] = *b"\xc0HELO\xc0";

    #[test]
    fn rx() -> Result<()> {
        let serial = Mock::new(&[Transaction::read_many(ENCODED)]);
        let mut slip = SlipDevice::from(serial);
        let (rx, _tx) = slip.receive().unwrap();
        rx.consume(Instant::from_millis(0), |buf| {
            assert_eq!(buf, DECODED);
            Ok(())
        })?;
        slip.as_mut().done();
        Ok(())
    }

    #[test]
    fn tx() -> Result<()> {
        let serial = Mock::new(&[Transaction::write_many(ENCODED)]);
        let mut slip = SlipDevice::from(serial);
        let tx = slip.transmit().unwrap();
        tx.consume(Instant::from_millis(0), 4, |buf| {
            buf.copy_from_slice(&DECODED);
            Ok(())
        })?;
        slip.as_mut().done();
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn ping() -> Result<()> {
        const LOCAL_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 1]);
        const PEER_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 2]);

        SimpleLogger::new().init().ok();

        // create a fake SLIP device
        let device = Mock::new(&[]);

        // create an interface
        let device = SlipDevice::from(device);
        let mut iface = InterfaceBuilder::new(device, Vec::new())
            .ip_addrs([Ipv4Cidr::new(LOCAL_ADDR, 24).into()])
            .finalize();

        // create a socket
        let rx_metadata_storage = [PacketMetadata::EMPTY; 1];
        let rx_payload_storage = [0; 18];
        let rx_buffer = IcmpSocketBuffer::new(rx_metadata_storage, rx_payload_storage);
        let tx_metadata_storage = [PacketMetadata::EMPTY; 1];
        let tx_payload_storage = [0; 18];
        let tx_buffer = IcmpSocketBuffer::new(tx_metadata_storage, tx_payload_storage);
        let socket = IcmpSocket::new(rx_buffer, tx_buffer);
        let handle = iface.add_socket(socket);

        {
            info!("bind socket");
            let socket = iface.get_socket::<IcmpSocket>(handle);
            socket.bind(IcmpEndpoint::Ident(1)).unwrap();

            info!("send ping");
            let icmp_repr = Icmpv4Repr::EchoRequest {
                ident: 1,
                seq_no: 1,
                data: b"0123456789",
            };
            let ip_repr = Ipv4Repr {
                src_addr: LOCAL_ADDR,
                dst_addr: PEER_ADDR,
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
            socket.send_slice(icmp_packet.into_inner(), PEER_ADDR.into())?;

            // Check transmitted SLIP frame
            let ip_buf = ip_packet.into_inner();
            let slip_buf = encode(&ip_buf);
            iface.device_mut().as_mut().expect(&[
                Transaction::read_error(nb::Error::WouldBlock),
                Transaction::write_many(slip_buf),
                Transaction::read_error(nb::Error::WouldBlock),
            ]);
        }

        let timestamp = Instant::from_millis(0);
        assert!(iface.poll(timestamp)?);
        assert_eq!(iface.poll_delay(timestamp), None);
        iface.device_mut().as_mut().done();

        // Send response
        {
            let icmp_repr = Icmpv4Repr::EchoReply {
                ident: 1,
                seq_no: 1,
                data: b"0123456789",
            };
            let ip_repr = Ipv4Repr {
                src_addr: PEER_ADDR,
                dst_addr: LOCAL_ADDR,
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

            let slip_buf = encode(&buf);
            iface.device_mut().as_mut().expect(&[
                Transaction::read_many(slip_buf),
                Transaction::read_error(nb::Error::WouldBlock),
                Transaction::read_error(nb::Error::WouldBlock),
            ]);
        }

        assert!(iface.poll(Instant::from_millis(0))?);
        assert_eq!(iface.poll_delay(Instant::from_millis(0)), None);
        iface.device_mut().as_mut().done();

        {
            info!("receive pong");
            let socket = iface.get_socket::<IcmpSocket>(handle);
            let (buf, addr) = socket.recv()?;
            assert_eq!(addr, PEER_ADDR.into());
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
