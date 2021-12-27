# smoltcp-slip

This crates aims to provide an implementation of the SLIP protocol for [smoltcp].

## Usage

```rust no_run
use linux_embedded_hal::Serial;
use smoltcp::iface::Interface;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use smoltcp_slip::SlipInterface;

// open a serial device
let device = Serial::open("/dev/ttyS0").expect("open serial port");

// create a SLIP interface from this device
let local_addr = Ipv4Cidr::new(Ipv4Address([192, 168, 1, 1]), 24);
let peer_addr = Ipv4Address([192, 168, 1, 2]);
let iface = SlipInterface::new(device, local_addr, peer_addr);

// convert it to an ethernet interface
let mut iface = Interface::from(iface);

// At this point, iface.poll() and the likes can be called.
```

[smoltcp]: https://github.com/smoltcp-rs/smoltcp