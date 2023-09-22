# smoltcp-slip

This crates aims to provide an implementation of the SLIP protocol for [smoltcp].

## Usage

```rust no_run
use linux_embedded_hal::Serial;
use smoltcp::iface::{Config, Interface};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, Ipv4Address, Ipv4Cidr};
use smoltcp_slip::SlipDevice;

// open a serial device
let device = Serial::open("/dev/ttyS0").expect("open serial port");

// create a SLIP device from this I/O device
let mut device = SlipDevice::from(device);

// create an interface from this IP device
let local_addr = Ipv4Cidr::new(Ipv4Address([192, 168, 1, 1]), 24);
let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::now());
iface.update_ip_addrs(|ips| { ips.push(local_addr.into()); });

// At this point, iface.poll() and the likes can be called.
```

[smoltcp]: https://github.com/smoltcp-rs/smoltcp
