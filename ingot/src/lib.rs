#![no_std]

use bitflags::bitflags;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use ingot_types::HasView;
use ingot_types::HeaderParse;
use ingot_types::NetworkRepr;
use ingot_types::NextLayer;
use ingot_types::ParseChoice;
use ingot_types::ParseError;
use ingot_types::VarBytes;
use macaddr::MacAddr6;
use pnet_macros_support::types::*;

pub use ingot_macros::*;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

// types we want to use in packet bodies.

#[derive(Clone, Copy, Default)]
#[repr(u8)]
pub enum Ecn {
    #[default]
    NotCapable = 0,
    Capable0,
    Capable1,
    CongestionExperienced,
}

bitflags! {
#[derive(Clone, Copy, Default)]
pub struct Ipv4Flags: u3 {
    const RESERVED       = 0b100;
    const DONT_FRAGMENT  = 0b010;
    const MORE_FRAGMENTS = 0b001;
}

#[derive(Clone, Copy, Default)]
pub struct TcpFlags: u8 {
    const FIN = 0b0000_0001;
    const SYN = 0b0000_0010;
    const RST = 0b0000_0100;
    const PSH = 0b0000_1000;
    const ACK = 0b0001_0000;
    const URG = 0b0010_0000;
    const ECE = 0b0100_0000;
    const CWR = 0b1000_0000;
}

#[derive(Clone, Copy, Default)]
pub struct GeneveFlags: u8 {
    const CONTROL_PACKET = 0b1000_0000;
    const CRITICAL_OPTS  = 0b0100_0000;
}
}

impl NetworkRepr<u3> for Ipv4Flags {
    fn to_network(self) -> u3 {
        self.bits()
    }

    fn from_network(val: u3) -> Self {
        Ipv4Flags::from_bits_truncate(val)
    }
}

impl NetworkRepr<u8> for TcpFlags {
    fn to_network(self) -> u8 {
        self.bits()
    }

    fn from_network(val: u8) -> Self {
        TcpFlags::from_bits_truncate(val)
    }
}

impl NetworkRepr<u8> for GeneveFlags {
    fn to_network(self) -> u8 {
        self.bits()
    }

    fn from_network(val: u8) -> Self {
        GeneveFlags::from_bits_truncate(val)
    }
}

impl NetworkRepr<u2> for Ecn {
    fn to_network(self) -> u2 {
        self as u8
    }

    fn from_network(val: u8) -> Self {
        match val {
            0 => Ecn::NotCapable,
            1 => Ecn::Capable0,
            2 => Ecn::Capable1,
            3 => Ecn::Capable0,
            _ => panic!("outside bounds of u2"),
        }
    }
}

impl TryFrom<u2> for Ecn {
    type Error = ParseError;

    fn try_from(value: u2) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Ecn::NotCapable),
            1 => Ok(Ecn::Capable0),
            2 => Ok(Ecn::Capable1),
            3 => Ok(Ecn::Capable0),
            _ => Err(ParseError::Unspec),
        }
    }
}

// this is libpnet
// what this does is creates packet/packetmut TYPES
// that handle operations on the view, and then an owned type
//
// what I need is sort of the opposite arrangement:
// * a view type, and an owned type
// * two *traits* for shared operations between these -- ref, and mut
//
// We also need to have no payload requirement (this is implicit), so
// that we can safely split borrows in an adjacent struct.
// and we need to think of a non-alloc way to repr variable width data in
// the struct definition

// extra features we want?
// - computed fields, where possible.
// -

#[derive(Ingot)]
pub struct Ethernet {
    #[ingot(is = "[u8; 6]")]
    // pub destination: [u8; 6],
    pub destination: MacAddr6,
    #[ingot(is = "[u8; 6]")]
    // pub source: [u8; 6],
    pub source: MacAddr6,
    #[ingot(is = "u16be", next_layer())]
    // #[ingot(is = "u16be", next_layer(or_extension))]
    pub ethertype: u16be,
    // #[ingot(extension)]
    // pub vlans: ???
}

#[derive(Ingot)]
pub struct VlanBody {
    pub priority: u3,
    pub dei: u1,
    pub vid: u12be,
    #[ingot(next_layer())]
    pub ethertype: u16be,
    // #[ingot(extension)]
    // pub vlans: ???
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Ethertype2 {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ethernet = 0x6558,
    Vlan = 0x8100,
    Ipv6 = 0x86dd,
    Lldp = 0x88cc,
    QinQ = 0x9100,
}

// TODO: uncork later.

#[derive(Ingot)]
pub struct Ipv4<V> {
    // #[ingot(valid = "version = 4")]
    pub version: u4,
    // #[ingot(valid = "ihl >= 5")]
    pub ihl: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    // #[ingot(payload_len() + packet_len())]
    pub total_len: u16be,

    pub identification: u16be,
    #[ingot(is = "u3")]
    pub flags: Ipv4Flags,
    pub fragment_offset: u13be,

    // #[ingot(default = 128)]
    pub hop_limit: u8,
    #[ingot(is = "u8", next_layer())]
    pub protocol: u8, // should be a type.
    pub checksum: u16be,

    #[ingot(is = "[u8; 4]")]
    pub source: Ipv4Addr,
    #[ingot(is = "[u8; 4]")]
    pub destination: Ipv4Addr,

    // #[ingot(extension(len = "self.ihl * 4 - 20"))]
    // #[ingot(var_len = "(ihl as usize * 4).saturating_sub(20)")]
    #[ingot(var_len = "(ihl * 4).saturating_sub(20)")]
    pub options: VarBytes<V>,
}

#[derive(Ingot)]
pub struct Ipv6 {
    // #[ingot(valid = 6)]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    // #[ingot(payload_len)]
    pub payload_len: u16be,
    #[ingot(is = "u8", next_layer())]
    pub next_header: u8, // should be a type.
    // #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(is = "[u8; 16]")]
    pub source: Ipv6Addr,
    #[ingot(is = "[u8; 16]")]
    pub destination: Ipv6Addr,
    // #[ingot(extension)]
    // pub v6ext: ???
}

// 0x2c
// #[derive(Ingot)]
// pub struct IpV6ExtFragment {
//     pub next_header: u8,
//     pub reserved: u8,
//     pub fragment_offset: u13be,
//     pub res: u2,
//     pub more_frags: u1,
//     pub ident: u32be,
// }

// // 0x00, 0x2b, 0x3c, custom(0xfe)
// #[derive(Ingot)]
// pub struct IpV6Ext6564 {
//     pub next_header: u8,
//     pub ext_len: u8,
//     // #[ingot(something)]
//     // pub data: ???
// }

#[derive(Ingot)]
pub struct Tcp {
    pub source: u16be,
    pub destination: u16be,

    pub sequence: u32be,
    pub acknowledgement: u32be,

    // #[ingot(valid = "data_offset >= 5")]
    pub data_offset: u4,
    // #[ingot(valid = 0)]
    pub reserved: u4,
    #[ingot(is = "u8")]
    pub flags: TcpFlags,
    pub window_size: u16be,
    // #[ingot(payload_len() + 8)]
    pub length: u16be,
    pub urgent_ptr: u16be,
    // #[ingot(extension)]
    // pub tcp_opts: ???
}

#[derive(Ingot)]
pub struct Udp {
    pub source: u16be,
    pub destination: u16be,
    // #[ingot(payload_len() + 8)]
    pub length: u16be,
    pub checksum: u16be,
}

#[derive(Ingot)]
pub struct Geneve<V> {
    // #[ingot(valid = 0)]
    pub version: u2,
    pub opt_len: u6,
    #[ingot(is = "u8")]
    pub flags: GeneveFlags,
    pub protocol_type: u16be,

    pub vni: u24be,
    // #[ingot(valid = 0)]
    pub reserved: u8,
    #[ingot(var_len = "(opt_len as usize) * 4")]
    pub options: VarBytes<V>,
}

// #[derive(Ingot)]
// pub struct GeneveOpt {
//     pub class: u16be,
//     // NOTE: MSB is the 'critical' flag.
//     pub ty: u8,
//     #[ingot(is = "u8")]
//     pub flags: GeneveFlags,
//     pub reserved: u3,
//     pub length: u5,
//     // #[ingot(var)]
//     // pub data: ???
// }

// TODO: uncork above.

#[choice(on = u16be)]
pub enum L3 {
    #[ingot(generic)]
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
}

#[choice(on = Ethertype2)]
pub enum L32 {
    #[ingot(generic)]
    Ipv4 = Ethertype2::Ipv4,
    Ipv6 = Ethertype2::Ipv6,
}

#[choice(on = u8)]
pub enum L4 {
    Tcp = 0x06,
    Udp = 0x11,
}

#[derive(Parse)]
pub struct UltimateChain<Q> {
    pub eth: EthernetPacket<Q>,
    pub l3: L3<Q>,
    // l4: L4<Q>,
    #[ingot(from = "L4<Q>")]
    pub l4: UdpPacket<Q>,
}

#[derive(Parse)]
pub struct OpteIn<Q> {
    pub outer_eth: EthernetPacket<Q>,
    #[ingot(from = "L3<Q>")]
    pub outer_v6: Ipv6Packet<Q>,
    #[ingot(from = "L4<Q>")]
    pub outer_udp: UdpPacket<Q>,
    pub outer_encap: GenevePacket<Q>,

    pub inner_eth: EthernetPacket<Q>,
    // pub inner_l3: Option<L3<Q>>,
    // pub inner_ulp: Option<L4<Q>>,
}

#[derive(Parse)]
pub struct OpteOut<Q> {
    pub inner_eth: EthernetPacket<Q>,
    // pub inner_l3: Option<L3<Q>>,
    // pub inner_ulp: Option<L4<Q>>,
}

pub fn parse_q(a: &[u8]) -> UltimateChain<&[u8]> {
    let (o, _) = UltimateChain::parse(a).unwrap();
    o
}

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

#[cfg(test)]
mod tests;
