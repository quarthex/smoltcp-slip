use core::mem::take;
use embedded_hal::serial::{Read, Write};
use log::error;
use slip_codec::{encode, Decoder};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::Result;
use std::collections::VecDeque;
use std::io;

pub struct Slip<T> {
    serial: T,
    decoder: Decoder,
    tx: VecDeque<u8>,
    rx: Vec<u8>,
}

impl<T> Slip<T>
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

impl<'a, T> Device<'a> for Slip<T>
where
    T: 'a + Read<u8> + Write<u8>,
{
    type RxToken = SlipRxToken<'a>;
    type TxToken = SlipTxToken<'a, T>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        Slip::drain(&mut self.serial, &mut self.tx);
        loop {
            match self.serial.read() {
                Ok(b) => match self.decoder.decode(&mut &[b][..], &mut self.rx) {
                    Ok(size) => {
                        debug_assert!(self.rx.len() == size);
                        let Self { serial, tx, rx, .. } = self;
                        let rx_token = Self::RxToken { rx };
                        let tx_token = Self::TxToken { serial, tx };
                        return Some((rx_token, tx_token));
                    }
                    Err(slip_codec::Error::FramingError) => {
                        error!("framing error")
                    }
                    Err(slip_codec::Error::OversizedPacket) => unimplemented!(),
                    Err(slip_codec::Error::EndOfStream) => {}
                    Err(slip_codec::Error::ReadError(..)) => unimplemented!(),
                },
                Err(nb::Error::Other(..)) => {
                    error!("failed to read from the serial port");
                    return None;
                }
                Err(nb::Error::WouldBlock) => return None,
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
        capabilities.max_transmission_unit = (std::usize::MAX - 2) / 2;
        capabilities
    }
}

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
        struct VecDequeWrap<'a>(&'a mut VecDeque<u8>);

        impl io::Write for VecDequeWrap<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.extend(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let Self { serial, tx } = self;
        let mut buf = vec![0; len];
        let res = f(&mut buf)?;
        tx.reserve(len * 2 + 2);
        encode(&buf, &mut VecDequeWrap(tx)).unwrap();
        Slip::drain(serial, tx);
        Ok(res)
    }
}

impl<T> From<T> for Slip<T> {
    fn from(serial: T) -> Self {
        Self {
            serial,
            decoder: Decoder::new(),
            tx: VecDeque::new(),
            rx: Vec::new(),
        }
    }
}

impl<T> AsRef<T> for Slip<T> {
    fn as_ref(&self) -> &T {
        &self.serial
    }
}

impl<T> AsMut<T> for Slip<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::Slip;
    use embedded_hal_mock::serial::{Mock, Transaction};
    use smoltcp::phy::{Device, RxToken, TxToken};
    use smoltcp::time::Instant;
    use smoltcp::Result;

    const DECODED: [u8; 4] = *b"HELO";
    const ENCODED: [u8; 6] = *b"\xc0HELO\xc0";

    #[test]
    fn rx() -> Result<()> {
        let serial = Mock::new(&[Transaction::read_many(ENCODED)]);
        let mut slip = Slip::from(serial);
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
        let mut slip = Slip::from(serial);
        let tx = slip.transmit().unwrap();
        tx.consume(Instant::from_millis(0), 4, |buf| {
            buf.copy_from_slice(&DECODED);
            Ok(())
        })?;
        slip.as_mut().done();
        Ok(())
    }
}
