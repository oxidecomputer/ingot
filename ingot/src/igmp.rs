// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ingot_macros::Ingot;
use ingot_types::{primitives::*, util::Repeated, Ipv4Addr, Vec};

/// See RFC3376, §4
#[derive(
    Clone,
    Copy,
    Hash,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
)]
#[repr(C)]
pub struct IgmpMessageType(pub u8);

impl IgmpMessageType {
    pub const MEMBERSHIP_QUERY: Self = Self(0x11);
    pub const V3_MEMBERSHIP_REPORT: Self = Self(0x22);
    pub const V1_MEMBERSHIP_REPORT: Self = Self(0x12);
    pub const V2_MEMBERSHIP_REPORT: Self = Self(0x16);
    pub const V2_LEAVE_GROUP: Self = Self(0x17);
}

/// See RFC3376, §4.1
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IgmpMembershipQuery {
    #[ingot(zerocopy, default = IgmpMessageType::MEMBERSHIP_QUERY)]
    pub ty: IgmpMessageType,
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
    #[ingot(zerocopy, default = IgmpMessageType::V3_MEMBERSHIP_REPORT)]
    pub ty: IgmpMessageType,
    resv1: u8,
    pub checksum: u16be,
    resv2: u16be,
    pub num_group_records: u16be, // not used, we just read the remaining data
    #[ingot(subparse())]
    pub group_records: Repeated<IgmpV3GroupRecord>,
    // XXX the RFC specifies that additional data may be present and should be
    // used in the checksum, but we're assuming that group records are the rest
    // of the packet (because their size isn't fully specified)
}

/// See RFC3376, §4.2.12
#[derive(
    Clone,
    Copy,
    Hash,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
)]
pub struct IgmpV3RecordType(pub u8);

impl IgmpV3RecordType {
    pub const MODE_IS_INCLUDE: Self = Self(1);
    pub const MODE_IS_EXCLUDE: Self = Self(2);
    pub const CHANGE_TO_INCLUDE_MODE: Self = Self(3);
    pub const CHANGE_TO_EXCLUDE_MODE: Self = Self(4);
}

/// See RFC3376, §4.2
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct IgmpV3GroupRecord {
    #[ingot(zerocopy)]
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
    #[ingot(zerocopy, default = IgmpMessageType::V2_MEMBERSHIP_REPORT)]
    pub ty: IgmpMessageType,
    pub max_resp: u8,
    pub checksum: u16be,
    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub group_address: Ipv4Addr,
}

/// See RFC2236, §2
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IgmpV2LeaveGroup {
    #[ingot(zerocopy, default = IgmpMessageType::V2_LEAVE_GROUP)]
    pub ty: IgmpMessageType,
    pub max_resp: u8,
    pub checksum: u16be,
    #[ingot(zerocopy, default = Ipv4Addr::UNSPECIFIED)]
    pub group_address: Ipv4Addr,
}
// XXX should these be the same type, since they only differ in `ty`?
