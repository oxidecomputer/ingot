// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ingot_macros::Ingot;
use ingot_types::{primitives::*, Vec};

ingot_types::zerocopy_type!(
    #[derive(Default)]
    pub struct IcmpV4Type(pub u8)
);

impl IcmpV4Type {
    pub const ECHO_REPLY: Self = Self(0);
    pub const DESTINATION_UNREACHABLE: Self = Self(3);
    pub const SOURCE_QUENCH: Self = Self(4);
    pub const REDIRECT: Self = Self(5);
    pub const ECHO: Self = Self(8);
    pub const ROUTER_ADVERTISEMENT: Self = Self(9);
    pub const ROUTER_SOLICITATION: Self = Self(10);
    pub const TIME_EXCEEDED: Self = Self(11);
    pub const PARAMETER_PROBLEM: Self = Self(12);
    pub const TIMESTAMP: Self = Self(13);
    pub const TIMESTAMP_REPLY: Self = Self(14);

    /// This packet's payload
    pub const fn payload_is_packet(self) -> bool {
        matches!(
            self,
            Self::DESTINATION_UNREACHABLE
                | Self::SOURCE_QUENCH
                | Self::REDIRECT
                | Self::TIME_EXCEEDED
                | Self::PARAMETER_PROBLEM
        )
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IcmpV4 {
    #[ingot(zerocopy)]
    pub ty: IcmpV4Type,
    pub code: u8,
    pub checksum: u16be,
    pub rest_of_hdr: [u8; 4],
}

ingot_types::zerocopy_type!(
    #[derive(Default)]
    pub struct IcmpV6Type(pub u8)
);

impl IcmpV6Type {
    pub const RESERVED: Self = Self(0);
    pub const DESTINATION_UNREACHABLE: Self = Self(1);
    pub const PACKET_TOO_BIG: Self = Self(2);
    pub const TIME_EXCEEDED: Self = Self(3);
    pub const PARAMETER_PROBLEM: Self = Self(4);
    pub const RESERVED_ERR: Self = Self(127);

    pub const ECHO_REQUEST: Self = Self(128);
    pub const ECHO_REPLY: Self = Self(129);
    pub const MULTICAST_LISTENER_QUERY: Self = Self(130);
    pub const MULTICAST_LISTENER_REPORT: Self = Self(131);
    pub const MULTICAST_LISTENER_DONE: Self = Self(132);
    pub const ROUTER_SOLICITATION: Self = Self(133);
    pub const ROUTER_ADVERTISEMENT: Self = Self(134);
    pub const NEIGHBOR_SOLICITATION: Self = Self(135);
    pub const NEIGHBOR_ADVERTISEMENT: Self = Self(136);
    pub const REDIRECT: Self = Self(137);
    pub const ROUTER_RENUMBER: Self = Self(138);
    pub const RESERVED_INFO: Self = Self(255);

    /// This packet's payload
    pub const fn payload_is_packet(self) -> bool {
        matches!(
            self,
            Self::DESTINATION_UNREACHABLE
                | Self::TIME_EXCEEDED
                | Self::PARAMETER_PROBLEM
                | Self::PACKET_TOO_BIG
        )
    }

    pub const fn is_error(self) -> bool {
        self.0 < 128
    }

    pub const fn is_informational(self) -> bool {
        self.0 >= 128
    }

    pub const fn is_neighbor_discovery(self) -> bool {
        self.0 >= Self::ROUTER_SOLICITATION.0 && self.0 <= Self::REDIRECT.0
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IcmpV6 {
    #[ingot(zerocopy)]
    pub ty: IcmpV6Type,
    pub code: u8,
    pub checksum: u16be,
    pub rest_of_hdr: [u8; 4],
}

pub mod ndisc {
    //! Header types related to the Neighbor Discovery Protocol within ICMPv6.
    use bitflags::bitflags;
    use ingot_types::{Ipv6Addr, NetworkRepr};

    use super::*;

    ingot_types::zerocopy_type!(
        #[derive(Default)]
        pub struct OptionType(pub u8)
    );

    impl OptionType {
        pub const SOURCE_LL_ADDRESS: Self = Self(1);
        pub const TARGET_LL_ADDRESS: Self = Self(2);
        pub const PREFIX_INFO: Self = Self(3);
        pub const REDIRECTED_HEADER: Self = Self(4);
        pub const MTU: Self = Self(5);
    }

    #[derive(Clone, Debug, Eq, PartialEq, Ingot)]
    pub struct Option {
        #[ingot(zerocopy, next_layer)]
        pub ty: OptionType,
        pub len: u8,
        #[ingot(var_len = "6 + (len.wrapping_sub(1) as usize) * 8")]
        pub data: Vec<u8>,
    }

    bitflags! {
    #[derive(Clone, Copy, Default, Debug, Hash, Eq, PartialEq)]
    pub struct PrefixFlags: u8 {
        const ON_LINK = 0b1000_0000;
        const AUTONOMOUS_ADDRESS_CONFIG = 0b0100_0000;
    }
    }

    impl NetworkRepr<u8> for PrefixFlags {
        fn to_network(self) -> u8 {
            self.bits()
        }

        fn from_network(val: u8) -> Self {
            PrefixFlags::from_bits_truncate(val)
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq, Ingot)]
    pub struct OptionPrefix {
        pub prefix_len: u8,
        #[ingot(is = "u8")]
        pub flags: PrefixFlags,
        pub valid_lifetime: u32be,
        pub preferred_lifetime: u32be,
        rsvd: u32be,
        #[ingot(zerocopy)]
        pub prefix: Ipv6Addr,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Ingot)]
    #[ingot(impl_default)]
    pub struct OptionRedirect {
        rsvd: [u8; 6],
        #[ingot(var_len)]
        pub data: Vec<u8>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Ingot)]
    #[ingot(impl_default)]
    pub struct OptionMtu {
        rsvd: [u8; 2],
        pub mtu: u32be,
    }
}
