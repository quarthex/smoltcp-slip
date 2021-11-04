use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::take;
use embedded_hal::serial::{Read, Write};
use log::error;
use serial_line_ip::{Decoder, Encoder};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
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
