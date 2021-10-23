use slip_codec::{encode, Decoder};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::Result;

pub struct Slip<T> {
    inner: T,
    decoder: Decoder,
}

impl<'a, T> Device<'a> for Slip<T>
where
    T: Device<'a>,
{
    type RxToken = SlipRxToken<'a, T::RxToken>;
    type TxToken = SlipTxToken<T::TxToken>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if let Some((rx_token, tx_token)) = self.inner.receive() {
            let rx_token = Self::RxToken {
                token: rx_token,
                decoder: &mut self.decoder,
            };
            let tx_token = Self::TxToken { token: tx_token };
            Some((rx_token, tx_token))
        } else {
            None
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        self.inner.transmit().map(|token| Self::TxToken { token })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = self.inner.capabilities();
        capabilities.max_transmission_unit = (capabilities.max_transmission_unit - 2) / 2;
        capabilities
    }
}

pub struct SlipRxToken<'a, T> {
    token: T,
    decoder: &'a mut Decoder,
}

impl<T> RxToken for SlipRxToken<'_, T>
where
    T: RxToken,
{
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { token, decoder } = self;
        token.consume(timestamp, |slip_buf| {
            let mut ip_buf = Vec::new();
            match decoder.decode(&mut &slip_buf[..], &mut ip_buf) {
                Ok(size) => {
                    debug_assert!(ip_buf.len() == size);
                    f(&mut ip_buf[..size])
                }
                Err(..) => unimplemented!(),
            }
        })
    }
}

pub struct SlipTxToken<T> {
    token: T,
}

impl<T> TxToken for SlipTxToken<T>
where
    T: TxToken,
{
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { token } = self;
        let mut buf = vec![0; len];
        let res = f(&mut buf)?;
        let mut slip = Vec::with_capacity(len * 2 + 2);
        let encoded_len = encode(&buf, &mut slip).unwrap();
        token.consume(timestamp, encoded_len, |buf| {
            buf.copy_from_slice(&slip);
            Ok(res)
        })
    }
}

impl<T> From<T> for Slip<T> {
    fn from(inner: T) -> Self {
        let decoder = Decoder::new();
        Self { inner, decoder }
    }
}

impl<T> AsRef<T> for Slip<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for Slip<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::Slip;
    use crate::tests::Mock;
    use smoltcp::phy::{Device, RxToken, TxToken};
    use smoltcp::time::Instant;
    use smoltcp::Result;

    const DECODED: [u8; 4] = *b"HELO";
    const ENCODED: [u8; 6] = *b"\xc0HELO\xc0";

    #[test]
    fn rx() -> Result<()> {
        let mut slip = Slip::from(Mock::default());
        slip.as_mut().rx = ENCODED.to_vec();
        let (rx, _tx) = slip.receive().unwrap();
        rx.consume(Instant::from_millis(0), |buf| {
            assert_eq!(buf, DECODED);
            Ok(())
        })
    }

    #[test]
    fn tx() -> Result<()> {
        let mut slip = Slip::from(Mock::default());
        let tx = slip.transmit().unwrap();
        tx.consume(Instant::from_millis(0), 4, |buf| {
            buf.copy_from_slice(&DECODED);
            Ok(())
        })?;
        assert_eq!(slip.as_ref().tx, ENCODED);
        Ok(())
    }
}
