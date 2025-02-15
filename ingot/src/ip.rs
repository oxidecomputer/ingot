// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bitflags::bitflags;
use ingot_macros::{choice, Ingot};
use ingot_types::{
    primitives::*, util::Repeated, Ipv4Addr, Ipv6Addr, NetworkRepr, ParseError,
    Vec,
};

ingot_types::zerocopy_type!(pub struct IpProtocol(pub u8));

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum ExtHdrClass {
    FragmentHeader,
    Rfc6564,
}

impl IpProtocol {
    pub const ICMP: Self = Self(1);
    pub const IGMP: Self = Self(2);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const ICMP_V6: Self = Self(58);
    pub const IPV6_NO_NH: Self = Self(59);

    // Not considered here: ESP (50) or AH (51).
    pub const IPV6_HOP_BY_HOP: Self = Self(0);
    pub const IPV6_ROUTE: Self = Self(43);
    pub const IPV6_FRAGMENT: Self = Self(44);
    pub const IPV6_DEST_OPTS: Self = Self(60);
    pub const IPV6_MOBILITY: Self = Self(135);
    pub const IPV6_HIP: Self = Self(139);
    pub const IPV6_SHIM6: Self = Self(140);
    pub const LAST_UNASSIGNED: Self = Self(252);
    pub const IPV6_EXPERIMENT0: Self = Self(253);
    pub const IPV6_EXPERIMENT1: Self = Self(254);

    #[inline]
    pub fn class(self) -> Option<ExtHdrClass> {
        match self {
            Self::IPV6_FRAGMENT => Some(ExtHdrClass::FragmentHeader),
            Self::IPV6_HOP_BY_HOP
            | Self::IPV6_ROUTE
            | Self::IPV6_DEST_OPTS
            | Self::IPV6_MOBILITY
            | Self::IPV6_HIP
            | Self::IPV6_SHIM6
            | Self::IPV6_EXPERIMENT0
            | Self::IPV6_EXPERIMENT1 => Some(ExtHdrClass::Rfc6564),
            _ => None,
        }
    }
}

impl Default for IpProtocol {
    fn default() -> Self {
        Self::LAST_UNASSIGNED
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ipv4 {
    #[ingot(default = 4)]
    pub version: u4,
    #[ingot(default = 5)]
    pub ihl: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub total_len: u16be,

    pub identification: u16be,
    #[ingot(is = "u3")]
    pub flags: Ipv4Flags,
    pub fragment_offset: u13be,

    #[ingot(default = 128)]
    pub hop_limit: u8,
    #[ingot(zerocopy, next_layer)]
    pub protocol: IpProtocol,
    pub checksum: u16be,

    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub source: Ipv4Addr,
    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub destination: Ipv4Addr,

    #[ingot(var_len = "(ihl * 4).saturating_sub(20)")]
    pub options: Vec<u8>,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Ecn {
    #[default]
    NotCapable = 0,
    Capable0,
    Capable1,
    CongestionExperienced,
}

impl NetworkRepr<u2> for Ecn {
    fn to_network(self) -> u2 {
        self as u8
    }

    #[inline]
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

    #[inline]
    fn try_from(value: u2) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Ecn::NotCapable),
            1 => Ok(Ecn::Capable0),
            2 => Ok(Ecn::Capable1),
            3 => Ok(Ecn::Capable0),
            _ => Err(ParseError::IllegalValue),
        }
    }
}

bitflags! {
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Hash)]
pub struct Ipv4Flags: u3 {
    const RESERVED       = 0b100;
    const DONT_FRAGMENT  = 0b010;
    const MORE_FRAGMENTS = 0b001;
}
}

impl NetworkRepr<u3> for Ipv4Flags {
    #[inline]
    fn to_network(self) -> u3 {
        self.bits()
    }

    #[inline]
    fn from_network(val: u3) -> Self {
        Ipv4Flags::from_bits_truncate(val)
    }
}

// #[derive(Clone, Debug, Eq, PartialEq, Hash, Ingot)]
#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct Ipv6 {
    #[ingot(default = "6")]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    pub payload_len: u16be,
    #[ingot(zerocopy, next_layer)]
    pub next_header: IpProtocol,
    #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(zerocopy, default = Ipv6Addr::UNSPECIFIED)]
    pub source: Ipv6Addr,
    #[ingot(zerocopy, default = Ipv6Addr::UNSPECIFIED)]
    pub destination: Ipv6Addr,

    #[ingot(subparse(on_next_layer))]
    pub v6ext: Repeated<LowRentV6EhRepr>,
}

#[choice(on = "IpProtocol", map_on = IpProtocol::class)]
pub enum LowRentV6Eh {
    IpV6ExtFragment = Some(ExtHdrClass::FragmentHeader),
    IpV6Ext6564 = Some(ExtHdrClass::Rfc6564),
}

// 0x2c
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct IpV6ExtFragment {
    #[ingot(zerocopy, next_layer)]
    pub next_header: IpProtocol, // should be a type.
    pub reserved: u8,
    pub fragment_offset: u13be,
    pub res: u2,
    pub more_frags: u1,
    pub ident: u32be,
}

// 0x00, 0x2b, 0x3c, custom(0xfe)
#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
pub struct IpV6Ext6564 {
    #[ingot(zerocopy, next_layer)]
    pub next_header: IpProtocol, // should be a type.
    pub ext_len: u8,

    #[ingot(var_len = "6 + (ext_len as usize) * 8")]
    pub data: Vec<u8>,
}
