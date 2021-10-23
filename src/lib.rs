#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod iface;
mod phy;
#[cfg(test)]
mod tests;

pub use iface::Interface as SlipInterface;
