// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ingot_macros::Ingot;
use ingot_types::{primitives::*, util::Repeated, Ipv4Addr, NetworkRepr, Vec};

/// See RFC3376, §4.1
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IgmpMembershipQuery {
    #[ingot(default = 0x11)]
    pub ty: u8,
    pub max_resp: u8,
    pub checksum: u16be,
    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub group_address: Ipv4Addr,
    resv: u4, // padding

    pub s: u1,
    pub qrv: u3,
    pub qqic: u8,
    pub num_sources: u16be,

    #[ingot(zerocopy, var_len = "num_sources.get()")]
    pub source_addrs: Vec<Ipv4Addr>,
    // XXX the RFC specifies that additional data may be present and should be
    // used in the checksum; how do we parse that?
}

/// See RFC3376, §4.2
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IgmpV3MembershipReport {
    #[ingot(default = 0x22)]
    pub ty: u8,
    resv1: u8,
    pub checksum: u16be,
    resv2: u16be,
    pub num_group_records: u16be,
    #[ingot(subparse())]
    pub group_records: Repeated<IgmpV3GroupRecord>,
}

/// See RFC3376, §4.2.12
#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct IgmpV3RecordType(pub u8);

impl IgmpV3RecordType {
    pub const MODE_IS_INCLUDE: Self = Self(1);
    pub const MODE_IS_EXCLUDE: Self = Self(2);
    pub const CHANGE_TO_INCLUDE_MODE: Self = Self(3);
    pub const CHANGE_TO_EXCLUDE_MODE: Self = Self(4);
}

impl NetworkRepr<u8> for IgmpV3RecordType {
    #[inline]
    fn to_network(self) -> u8 {
        self.0
    }

    #[inline]
    fn from_network(val: u8) -> Self {
        Self(val)
    }
}

/// See RFC3376, §4.2
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct IgmpV3GroupRecord {
    #[ingot(is = "u8")]
    pub record_type: IgmpV3RecordType,
    pub aux_data_len: u8,
    pub num_sources: u16be,
    #[ingot(zerocopy)]
    pub multicast_addr: Ipv4Addr,

    #[ingot(zerocopy, var_len = "num_sources.get()")]
    pub source_addrs: Vec<Ipv4Addr>,
    #[ingot(var_len = "aux_data_len")]
    pub auxiliary_data: Vec<u8>,
}

/// See RFC2236, §2
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IgmpV2MembershipReport {
    #[ingot(default = 0x16)]
    pub ty: u8,
    pub max_resp: u8,
    pub checksum: u16be,
    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub group_address: Ipv4Addr,
}

/// See RFC2236, §2
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IgmpV2LeaveGroup {
    #[ingot(default = 0x17)]
    pub ty: u8,
    pub max_resp: u8,
    pub checksum: u16be,
    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub group_address: Ipv4Addr,
}
// XXX should these be the same type with a strong type for `ty`?
