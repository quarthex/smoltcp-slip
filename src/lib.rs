#![warn(clippy::cargo)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod iface;
mod phy;

pub use iface::Interface as SlipInterface;
