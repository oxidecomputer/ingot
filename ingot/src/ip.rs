use bitflags::bitflags;
use core::net::{Ipv4Addr, Ipv6Addr};
use ingot_macros::{choice, Ingot};
use ingot_types::{primitives::*, NetworkRepr, Packet, ParseError, VarBytes};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct IpProtocol(pub u8);

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum ExtHdrClass {
    NotAnEh,
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
    pub const IPV6_EXPERIMENT0: Self = Self(253);
    pub const IPV6_EXPERIMENT1: Self = Self(254);

    pub fn class(self) -> ExtHdrClass {
        match self {
            Self::IPV6_FRAGMENT => ExtHdrClass::FragmentHeader,
            Self::IPV6_HOP_BY_HOP
            | Self::IPV6_ROUTE
            | Self::IPV6_DEST_OPTS
            | Self::IPV6_MOBILITY
            | Self::IPV6_HIP
            | Self::IPV6_SHIM6
            | Self::IPV6_EXPERIMENT0
            | Self::IPV6_EXPERIMENT1 => ExtHdrClass::Rfc6564,
            _ => ExtHdrClass::NotAnEh,
        }
    }
}

impl NetworkRepr<u8> for IpProtocol {
    fn to_network(self) -> u8 {
        self.0
    }

    fn from_network(val: u8) -> Self {
        Self(val)
    }
}

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
    #[ingot(is = "u8", next_layer)]
    pub protocol: IpProtocol, // should be a type.
    pub checksum: u16be,

    #[ingot(is = "[u8; 4]")]
    pub source: Ipv4Addr,
    #[ingot(is = "[u8; 4]")]
    pub destination: Ipv4Addr,

    #[ingot(var_len = "(ihl * 4).saturating_sub(20)")]
    pub options: VarBytes<V>,
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

bitflags! {
#[derive(Clone, Copy, Default)]
pub struct Ipv4Flags: u3 {
    const RESERVED       = 0b100;
    const DONT_FRAGMENT  = 0b010;
    const MORE_FRAGMENTS = 0b001;
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

#[derive(Ingot)]
pub struct Ipv6<V> {
    // pub struct Ipv6 {
    // #[ingot(valid = 6)]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    // #[ingot(payload_len)]
    pub payload_len: u16be,
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol, // should be a type.
    // #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(is = "[u8; 16]")]
    pub source: Ipv6Addr,
    #[ingot(is = "[u8; 16]")]
    pub destination: Ipv6Addr,

    #[ingot(subparse(on_next_layer))]
    // // pub v6ext: V6Ehs<V>,//<V>,
    pub v6ext: LowRentV6Eh<V>,
}

#[choice(on = "IpProtocol", map_on = IpProtocol::class)]
pub enum LowRentV6Eh {
    IpV6ExtFragment = ExtHdrClass::FragmentHeader,
    #[ingot(generic)]
    IpV6Ext6564 = ExtHdrClass::Rfc6564,
}

// TODO
pub type V6Ehs<V> = Packet<(), ParseChoiceLoop<V6EhChoice<V>>>;

pub struct ParseChoiceLoop<T> {
    inner: T,
}

pub enum V6EhChoice<V> {
    A(V),
}

// 0x2c
#[derive(Ingot)]
pub struct IpV6ExtFragment {
    pub next_header: u8,
    pub reserved: u8,
    pub fragment_offset: u13be,
    pub res: u2,
    pub more_frags: u1,
    pub ident: u32be,
}

// 0x00, 0x2b, 0x3c, custom(0xfe)
#[derive(Ingot)]
pub struct IpV6Ext6564<V> {
    pub next_header: u8,
    pub ext_len: u8,

    #[ingot(var_len = "(ext_len as usize) * 8")]
    pub data: VarBytes<V>,
}
