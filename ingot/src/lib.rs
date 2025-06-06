// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![doc = include_str!("../README.md")]
//! # Usage
//! Packets and headers are defined using the procedural macros
//! [`Ingot`] (headers), [`choice`] (selecting between headers), and
//! [`Parse`] (chains of individual layers).
//!
//! The documentation for each macro (as well as the packet and header types)
//! defined here double as examples of their use. See also the `ingot-examples`
//! crate.
//!
//! Headers can be used directly (as with any other rust struct), or using
//! protocol-specific traits and the `Header` type when we need to hold mixed
//! owned/borrowed data.
//!
//! ```text
//! ╔═╗
//! ║P║   pub struct Packet<Owned, View> {      pub struct DirectPacket<Owned, View> {
//! ║r║       Repr(Box<Owned>),                     Repr(Owned),
//! ║o║       Raw(View),                            Raw(View),
//! ║v║   }                                     }
//! ║i║                   │                                         │
//! ║d║                   │                                         │
//! ║e║                   └───────────────┬────────IMPL─────────────┴──────┐
//! ║d║                                   │                                │
//! ╚═╝─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─
//!                                       ▼                                ▼
//! ╔═╗                     │ #[derive(Ingot)]           #[derive(Ingot)]
//! ║U║  #[derive(Ingot)]     pub trait UdpRef {         pub trait UdpMut {
//! ║s║  pub struct Udp {   │     fn src(&self) -> u16;      fn set_src(&mut self, val: u16);
//! ║e║      // ...        ──┐    fn dst(&self) -> u16;      fn set_dst(&mut self, val: u16);
//! ║r║  } ▲          │     ││    // ...                     // ...
//! ╚═╝    │          │      │}                          }
//!        │      HasView   ││            ▲                                ▲
//! ─ ─ ─ ─│─ ─ ─ ─ ─ ┼ ─ ─ ─│            │                                │
//!     HasRepr       │      ├────────────┴───────────IMPL─────────────────┘
//!        │          │      │
//!        │          │      │                                  ╔═══════════╗
//!        │          ▼                                         ║ Generated ║
//!    pub struct ValidUdp<B: ByteSlice> (                      ╚═══════════╝
//!        Ref<B, UdpPart0>, // Zerocopy, repr(C)
//!    );
//! ```
//!
//! Headers define *owned* and *borrowed* versions of their contents, with shared
//! traits to use and modify each individually or through the `Header` abstraction.
//! Base traits, primitive types, and assorted helpers are defined in [`ingot_types`].
//!
//! ## Working with packets.
//! Packets/headers can be read and modified whether they are owned or borrowed:
//! ```rust
//! use ingot::ethernet::{Ethernet, Ethertype, EthernetRef, EthernetMut, ValidEthernet};
//! use ingot::types::{Emit, HeaderParse, Header};
//! use macaddr::MacAddr6;
//!
//! let owned_ethernet = Ethernet {
//!     destination: MacAddr6::broadcast(),
//!     source: MacAddr6::nil(),
//!     ethertype: Ethertype::ARP,
//! };
//!
//! // ----------------
//! // Field reads.
//! // ----------------
//!
//! let emitted_ethernet = owned_ethernet.emit_vec();
//! let (reparsed_ethernet, ..) = ValidEthernet::parse(&emitted_ethernet[..]).unwrap();
//!
//! // via EthernetRef
//! assert_eq!(reparsed_ethernet.source(), MacAddr6::nil());
//!
//! // compile error!
//! // assert_eq!(reparsed_ethernet.set_source(), MacAddr6::nil());
//!
//! // ----------------
//! // Field mutation.
//! // ----------------
//!
//! let mut emitted_ethernet = emitted_ethernet;
//! let (mut rereparsed_ethernet, ..) = ValidEthernet::parse(&mut emitted_ethernet[..]).unwrap();
//! rereparsed_ethernet.set_source(MacAddr6::broadcast());
//! rereparsed_ethernet.set_destination(MacAddr6::nil());
//!
//! assert_eq!(rereparsed_ethernet.source(), MacAddr6::broadcast());
//! assert_eq!(rereparsed_ethernet.destination(), MacAddr6::nil());
//!
//! // ----------------
//! // ...and via Header
//! // ----------------
//! let eth_pkt = Header::from(rereparsed_ethernet);
//! assert_eq!(eth_pkt.source(), MacAddr6::broadcast());
//! ```
//!
//! Packets can also be written into any buffer easily for any tuple of headers:
//! ```rust
//! # use ingot::ethernet::{Ethernet, Ethertype, EthernetRef, EthernetMut, ValidEthernet};
//! # use ingot::types::{Emit, HeaderParse, Header};
//! # use macaddr::MacAddr6;
//! use ingot::geneve::*;
//! use ingot::udp::*;
//!
//! // Headers can be emitted on their own.
//! let owned_ethernet = Ethernet {
//!     destination: MacAddr6::broadcast(),
//!     source: MacAddr6::nil(),
//!     ethertype: Ethertype::ARP,
//! };
//!
//! let emitted_ethernet = owned_ethernet.emit_vec();
//! let (reparsed_ethernet, hint, rest) = ValidEthernet::parse(&emitted_ethernet[..]).unwrap();
//!
//! // Or we can easily emit an arbitrary stack in order
//! let makeshift_stack = (
//!     Udp { source: 1234, destination: 5678, length: 77, checksum: 0xffff },
//!     Geneve {
//!         flags: GeneveFlags::CRITICAL_OPTS,
//!         protocol_type: Ethertype::ETHERNET,
//!         vni: 7777.try_into().unwrap(),
//!         ..Default::default()
//!     },
//!     &[1, 2, 3, 4][..],
//!     reparsed_ethernet,
//! );
//!
//! // ...to a new buffer.
//! let out = makeshift_stack.emit_vec();
//!
//! // ...or to an existing one
//! let mut slot = [0u8; 1500];
//! let _remainder = makeshift_stack.emit_prefix(&mut slot[..]).unwrap();
//! ```

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
pub mod igmp;
pub mod ip;
pub mod tcp;
pub mod udp;

#[cfg(test)]
mod tests;
