//! test text hello.

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

// NOTE: below are some notes that help to remind me of what was initially
// planned. Keep here for now...

// Now how do we do these? unsafe trait?

// note: this is not parsable but it IS constructable.

// can construct but not parse
// type ProcessChain = (Option<InnerEncapChain>, PacketChain);

// can parse and construct
// type EncapChain = (InnerEncapChain, PacketChain);
// equiv:
// type EncapChain = (InnerEncapChain, (A, BChoice, C1));

// HeaderStack<T> ?

// NEED:
// * access to all remaining slices
// * A way to specify 'next header check' on packet types without one
//   - Part of `Chain`.
// * Remove this bloody HeaderStack type.
// * To

// REALLY NEED TO THINK ABOUT HOW/WHEN TO COMBINE PARSEDs
// - should always be possible to combine dyn with anything that can be expanded.
//

// main conditions: NO DYNS, NO PANICS, NO STRINGS, NO VECS IN BASE CASE

// maybe we want:
// #[parse]
// type PacketChain = (A, BChoice, CChoice);

// What we need is:
// - Our header chain specifies A -> B
// - A can elect a specific next packet type (T) from the source (S).
//   - It may fail!
//   - Folks may want to override this as an attr on the layer.
//     - Why? We don't want e.g. Geneve as a guaranteed followup on dst port/src port, and we only
//       want it in one direction.
// - T may be convertible to B. If so, we get a B -- otherwise an Err.
//   - How tf would we encode this? We can't go via negative impl on e.g. From.
//   - Should it be contingent on
//   - possibly:
//     - BChoice exposes check on 'valid values' of nh.
//     - We take out a T.
//     - We then convert from T to BChoice, which will now be infallible.
//   - We also want to bottle out early -- e.g. we see the NH for B5, then exit. Not parse B5 then fail to wrap as a BChoice.
//   - need procmacros to wrap this -- recall we want to store both zerocopy versions and dynamic versions.

// Don't want fold to need to handle *all* cases that we might encode as types.

// Options in packet chains are not parsable, but may be emitted.

//... Cksums are a 'tomorrow problem'.

// Broadly:
//  A parsed packet hides the underlying `inner`.
//  The parse state holds many pointers into the guts of the `inner`.
//  These pointers have a lifetime identical to the packet state.

// ---------------------------
//
// Maybe need to rethink some stuff around chain construction.
// - OPTE allows e.g. l2 only, to receive arp packets
// - e.g., an outbound packet does not need *all* layers.
// - an inbound packet does need all layers, though...
//
// What are the acceptable packet pathways?
// - OUT -- ETH + unparsed(ARP)
//       -- ETH + IPv4 + {TCP, UDP, ICMP}
//       -- ETH + IPv6 + {TCP, UDP, ICMPv6} (OPTE does not enforce the ICMP match)
// = (Ethernet, Option<Ip>, Option<Ulp>)
//
//          outer                         inner
// - IN  -- [ETH + IPv6 + UDP + Geneve] + [ETH + IPv4 + {TCP, UDP, ICMP}]
//       -- [ETH + IPv6 + UDP + Geneve] + [ETH + IPv6 + {TCP, UDP, ICMPv6}]
// = ((Ethernet, Ipv6, Udp, Geneve), (Ethernet, Ip, Ulp))
//   downgrade to
//   ((Ethernet, Ipv6, Udp, Geneve), (Ethernet, Option<Ip>, Option<Ulp>))
//
// PacketMeta should then be derived from the In/Out formats, giving us
// (Option<(Ethernet, Ipv6, Udp, Geneve)>, (Ethernet, Option<Ip>, Option<Ulp>))
//
// We need some ethertypes to be able to end parsing. This requires successor fields
// to be nullable.
// ...this is getting closer to P4, eh.
//
// Is there a way to represent these guys infallibly?
// OPTE has them all optional, and actions which check those fields
//
// How does encap look in OPTE?
// encap: This is one big HdrTransform, pushing all outer layers and modding InnerEther
// decap: pop outer layers.
//
// These fall into the HeaderAction camp.
// Mods are specifically field subsets.
