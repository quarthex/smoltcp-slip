#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod iface;
mod phy;

pub use iface::Interface as SlipInterface;
