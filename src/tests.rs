use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::Result;

#[derive(Default)]
pub struct Mock {
    pub rx: Vec<u8>,
    pub tx: Vec<u8>,
}

impl<'a> Device<'a> for Mock {
    type RxToken = MockToken<'a>;
    type TxToken = MockToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if self.rx.is_empty() {
            None
        } else {
            let Self { rx, tx } = self;
            Some((MockToken(rx), MockToken(tx)))
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(MockToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = usize::MAX;
        caps
    }
}

pub struct MockToken<'a>(&'a mut Vec<u8>);

impl RxToken for MockToken<'_> {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let res = f(&mut self.0[..]);
        self.0.drain(..);
        res
    }
}

impl TxToken for MockToken<'_> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        *self.0 = vec![0; len];
        f(&mut self.0[..])
    }
}
