#![warn(clippy::cargo)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

mod iface;
mod phy;

pub use embedded_hal;
pub use iface::SlipInterface;
pub use smoltcp;
