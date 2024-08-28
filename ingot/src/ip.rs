use bitflags::bitflags;
use core::net::{Ipv4Addr, Ipv6Addr};
use ingot_macros::{choice, Ingot};
use ingot_types::{
    primitives::*, HasBuf, HasRepr, HasView, Header, NetworkRepr, NextLayer,
    Packet, ParseChoice, ParseError, VarBytes, Vec,
};
use zerocopy::{ByteSlice, SplitByteSlice};

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

    #[inline]
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
    #[inline]
    fn to_network(self) -> u8 {
        self.0
    }

    #[inline]
    fn from_network(val: u8) -> Self {
        Self(val)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct Ipv4 {
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
            _ => Err(ParseError::Unspec),
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

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct Ipv6 {
    // #[ingot(valid = 6)]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    // #[ingot(payload_len)]
    pub payload_len: u16be,
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol,
    // #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(is = "[u8; 16]")]
    pub source: Ipv6Addr,
    #[ingot(is = "[u8; 16]")]
    pub destination: Ipv6Addr,
    // #[ingot(subparse(on_next_layer))]
    // // pub v6ext: V6Extensions<V>,
    // // pub v6ext: LowRentV6Eh<V>,
    // pub v6ext: RepeatedEh<V>,
}

// impl<V: ::ingot::types::SplitByteSlice> ::ingot::types::HeaderParse
// for ValidIpv6<V> {
//     type Target = Self;
//     fn parse(
//         from: V,
//     ) -> ::ingot::types::ParseResult<::ingot::types::Success<Self>> {
//         use ::ingot::types::Header;
//         use ::ingot::types::HasView;
//         use ::ingot::types::NextLayer;
//         use ::ingot::types::ParseChoice;
//         use ::ingot::types::HeaderParse;
//         let mut hint = None;
//         let (v0, from): (::zerocopy::Ref<_, _Ipv6_ingot_impl::Ipv6Part0>, _) = ::zerocopy::Ref::from_prefix(
//                 from,
//             )
//             .map_err(|_| ::ingot::types::ParseError::TooSmall)?;
//         hint = ::core::option::Option::Some(
//             ::ingot::types::NetworkRepr::from_network(v0.next_header),
//         );
//         let ::ingot::types::Success { val: v1, remainder: from, .. } = ValidRepeated::<ValidLowRentV6Eh<_>, _>::parse_choice(from, hint)?;
//         let v1 = v1.into();
//         let val = ValidIpv6(v0, v1);
//         hint = hint.or_else(|| val.next_layer());
//         ::core::result::Result::Ok(::ingot::types::Success {
//             val,
//             hint,
//             remainder: from,
//         })
//     }
// }

#[choice(on = "IpProtocol", map_on = IpProtocol::class)]
pub enum LowRentV6Eh {
    IpV6ExtFragment = ExtHdrClass::FragmentHeader,
    IpV6Ext6564 = ExtHdrClass::Rfc6564,
}

// TODO: generate
// impl<V> HasRepr for LowRentV6Eh<V> {
//     type ReprType = LowRentV6EhRepr;
// }

// impl<V> HasView<V> for LowRentV6EhRepr
// where
//     ValidLowRentV6Eh<V>: HasBuf<BufType = V>,
// {
//     type ViewType = ValidLowRentV6Eh<V>;
// }

// impl<V> HasRepr for ValidLowRentV6Eh<V> {
//     type ReprType = LowRentV6EhRepr;
// }

// impl<V> HasView<V> for ValidLowRentV6Eh<V>
// where
//     Self: HasBuf<BufType = V>,
// {
//     type ViewType = Self;
// }

// impl Header for LowRentV6EhRepr {
//     const MINIMUM_LENGTH: usize = 0;

//     fn packet_length(&self) -> usize {
//         todo!()
//     }
// }

// impl<'a> HasView<&'a [u8]> for Vec<LowRentV6Eh<LowRentV6EhRepr<&'a [u8]>>>
// {
//     type ViewType = ValidRepeatedEh<&'a [u8]>;
// }

// 0x2c
#[derive(Ingot)]
pub struct IpV6ExtFragment {
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol, // should be a type.
    pub reserved: u8,
    pub fragment_offset: u13be,
    pub res: u2,
    pub more_frags: u1,
    pub ident: u32be,
}

// 0x00, 0x2b, 0x3c, custom(0xfe)
#[derive(Ingot)]
pub struct IpV6Ext6564 {
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol, // should be a type.
    pub ext_len: u8,

    #[ingot(var_len = "(ext_len as usize) * 8")]
    pub data: Vec<u8>,
}

// TODO: Ideally, we want this as a combinator.
//       I fought with my collection of types and traits for like 4 hours
//       and was unable to make that happen -- We only *need* it for V6EHs
//       but it would be real nice to have for, e.g., Q-in-Q.
/*
pub type RepeatedEh<B> = Packet<Vec<LowRentV6EhRepr>, ValidRepeatedEh<B>>;

// impl<B: SplitByteSlice> From<&ValidRepeatedEh<B>> for Vec<LowRentV6EhRepr> {
//     fn from(value: &ValidRepeatedEh<B>) -> Self {
//         let mut out = alloc::vec![];
//         let mut hint = value.first_hint;
//         let mut to_read = value.inner;

//         while IpProtocol::class(hint) != ExtHdrClass::NotAnEh {
//             match <ValidLowRentV6Eh<B> as ParseChoice<B, IpProtocol>>::parse_choice(
//                 to_read,
//                 Some(hint),
//             ) {
//                 Ok((val, Some(l_hint), remainder)) => {
//                     to_read = remainder;
//                     // bytes_read = original_len - remainder.len();
//                     hint = l_hint;
//                     // TODO: derive froms on choices.
//                     let owned = match val {
//                         ValidLowRentV6Eh::IpV6ExtFragment(v) => LowRentV6EhRepr::IpV6ExtFragment((&v).into()),
//                         ValidLowRentV6Eh::IpV6Ext6564(v) => LowRentV6EhRepr::IpV6Ext6564((&v).into()),
//                     };
//                     out.push(owned);
//                 }
//                 Ok(_) | Err(ParseError::Unwanted) => unreachable!(),
//                 Err(_) => unreachable!()
//             }
//         }

//         out
//     }
// }

pub struct ValidRepeatedEh<B> {
    inner: B,
    first_hint: IpProtocol,
}

impl<B: SplitByteSlice> Iterator for &ValidRepeatedEh<B> {
    type Item = ValidLowRentV6Eh<B>;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

impl<B: ByteSlice> HasBuf for ValidRepeatedEh<B> {
    type BufType = B;
}

impl<B: ByteSlice> Header for ValidRepeatedEh<B> {
    const MINIMUM_LENGTH: usize = 0;

    #[inline]
    fn packet_length(&self) -> usize {
        self.inner.len()
    }
}

impl<B: ByteSlice> NextLayer for ValidRepeatedEh<B> {
    type Denom = IpProtocol;

    #[inline]
    fn next_layer(&self) -> Option<Self::Denom> {
        // TODO: scan to last and re-read.
        None
    }
}

impl<B> HasRepr for ValidRepeatedEh<B> {
    type ReprType = Vec<LowRentV6EhRepr>;
}

impl<B: SplitByteSlice> ParseChoice<B, IpProtocol> for ValidRepeatedEh<B> {
    #[inline]
    fn parse_choice(
        data: B,
        hint: Option<IpProtocol>,
    ) -> ingot_types::ParseResult<ingot_types::Success<Self>> {
        let original_len = data.len();
        let mut bytes_read = 0;
        let Some(mut hint) = hint else {
            return Err(ParseError::NeedsHint);
        };
        let first_hint = hint;

        while IpProtocol::class(hint) != ExtHdrClass::NotAnEh {
            match <ValidLowRentV6Eh<&[u8]> as ParseChoice<&[u8], IpProtocol>>::parse_choice(
                &data[bytes_read..],
                Some(hint),
            ) {
                Ok((.., Some(l_hint), remainder)) => {
                    bytes_read = original_len - remainder.len();
                    hint = l_hint;
                }
                Ok(_) | Err(ParseError::Unwanted) => unreachable!(),
                Err(e) => return Err(e),
            }
        }

        let (inner, remainder) = data.split_at(bytes_read);

        let val = Self { inner, first_hint };

        Ok((val, Some(hint), remainder))
    }
}

impl<B> From<ValidRepeatedEh<B>> for RepeatedEh<B> {
    #[inline]
    fn from(value: ValidRepeatedEh<B>) -> Self {
        Self::Raw(value)
    }
}
*/
