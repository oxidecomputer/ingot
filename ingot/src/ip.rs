use bitflags::bitflags;
use core::net::{Ipv4Addr, Ipv6Addr};
use ingot_macros::Ingot;
use ingot_types::{primitives::*, NetworkRepr, ParseError, VarBytes};

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
