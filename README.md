# smoltcp-slip

This crates aims to provide an implementation of the SLIP protocol for [smoltcp].

## Usage

```rust no_run
use linux_embedded_hal::Serial;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use smoltcp_slip::SlipDevice;

// open a serial device
let device = Serial::open("/dev/ttyS0").expect("open serial port");

// create a SLIP device from this I/O device
let device = SlipDevice::from(device);

// create an interface from this IP device
let local_addr = Ipv4Cidr::new(Ipv4Address([192, 168, 1, 1]), 24);
let mut iface = InterfaceBuilder::new(device, Vec::new())
    .ip_addrs([local_addr.into()])
    .finalize();

// At this point, iface.poll() and the likes can be called.
```

[smoltcp]: https://github.com/smoltcp-rs/smoltcp
