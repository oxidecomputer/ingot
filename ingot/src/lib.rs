#![doc = include_str!("../../README.md")]
//! # Usage
//! Packets and headers are defined using the procedural macros
//! [`Ingot`] (headers), [`choice`] (selecting between headers), and
//! [`Parse`] (chains of individual layers).
//!
//! The documentation for each macro (as well as the packet and header types)
//! defined here double as examples of their use.
//!
//! Headers can be used directly (as with any other rust struct), or using
//! protocol-specific traits and the `Packet` type when we need to hold mixed
//! owned/borrowed data.
//!
//! ![Visual relationship between owned and borrowed types in Ingot.](https://raw.githubusercontent.com/oxidecomputer/ingot/refs/heads/prototype/model.svg?token=GHSAT0AAAAAACJJQVH7NSUC23YG654MM5KWZYEDKPA "Visual relationship between owned and borrowed types in Ingot.")
//!
//! Headers define *owned* and *borrowed* versions of their contents, with shared
//! traits to use and modify each individually or through the `Packet` abstraction.

#![no_std]

// This lets us consistently use ::ingot::types regardless
// of call site in the macro (i.e., our code or downstream user
// packets).
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
