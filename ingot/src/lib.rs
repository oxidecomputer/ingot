#![doc = include_str!("../../README.md")]
#![no_std]

// This lets us consistently use ::ingot::types regardless
// of call site in the macro.
extern crate self as ingot;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub use ingot_macros::{choice, Ingot, Parse};

/// Primitive types and core traits needed to generate and use
/// `ingot` packets.
pub use ingot_types as types;

pub mod ethernet;
pub mod geneve;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod udp;

pub mod example_chain;

#[cfg(test)]
mod tests;
