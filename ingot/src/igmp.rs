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
    // There may be additional trailing data in the packet, which should be used
    // when computing the checksum.
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
    // There may be additional trailing data in the packet, which should be used
    // when computing the checksum.
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

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)]
mod test {
    use super::*;
    use crate::types::{Header, HeaderParse};

    #[test]
    fn parse() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x11,
            0x00,
            0x00, 0x00,
            1, 4, 6, 8,
            0b0000_0_010, 64,
            0x00, 0x05,

            2, 2, 2, 2,
            2, 2, 2, 3,
            2, 2, 2, 4,
            2, 2, 2, 5,
            2, 2, 2, 6,
        ][..];
        let (igmp, ..) = ValidIgmpMembershipQuery::parse(bytes).unwrap();
        assert_eq!(igmp.ty(), IgmpMessageType::MEMBERSHIP_QUERY);
        assert_eq!(igmp.max_resp(), 0);
        assert_eq!(igmp.checksum(), 0);
        assert_eq!(igmp.group_address(), Ipv4Addr::from_octets([1, 4, 6, 8]));
        assert_eq!(igmp.qrv(), 0b10);
        assert_eq!(igmp.qqic(), 64);
        assert_eq!(igmp.num_sources(), 5);

        match igmp.source_addrs_ref() {
            ingot_types::FieldRef::Repr(_a) => todo!("owned"),
            ingot_types::FieldRef::Raw(Header::Repr(_a)) => todo!("also owned"),
            ingot_types::FieldRef::Raw(Header::Raw(ips)) => {
                assert_eq!(ips.len(), 5);
                assert_eq!(ips[0], Ipv4Addr::from_octets([2, 2, 2, 2]));
                assert_eq!(ips[1], Ipv4Addr::from_octets([2, 2, 2, 3]));
                assert_eq!(ips[2], Ipv4Addr::from_octets([2, 2, 2, 4]));
                assert_eq!(ips[3], Ipv4Addr::from_octets([2, 2, 2, 5]));
                assert_eq!(ips[4], Ipv4Addr::from_octets([2, 2, 2, 6]));
            }
        }
    }

    #[test]
    fn parse_mut() {
        #[rustfmt::skip]
        let bytes: &mut [u8] = &mut [
            0x11,
            0x00,
            0x00, 0x00,
            1, 4, 6, 8,
            0b0000_0_010, 64,
            0x00, 0x05,

            2, 2, 2, 2,
            2, 2, 2, 3,
            2, 2, 2, 4,
            2, 2, 2, 5,
            2, 2, 2, 6,
        ][..];
        let (mut igmp, ..) =
            ValidIgmpMembershipQuery::parse(&mut bytes[..]).unwrap();

        match igmp.source_addrs_mut() {
            ingot_types::FieldMut::Repr(_a) => todo!("owned"),
            ingot_types::FieldMut::Raw(Header::Repr(_a)) => todo!("also owned"),
            ingot_types::FieldMut::Raw(Header::Raw(ips)) => {
                assert_eq!(ips.len(), 5);
                assert_eq!(ips[0], Ipv4Addr::from_octets([2, 2, 2, 2]));
                assert_eq!(ips[1], Ipv4Addr::from_octets([2, 2, 2, 3]));
                assert_eq!(ips[2], Ipv4Addr::from_octets([2, 2, 2, 4]));
                assert_eq!(ips[3], Ipv4Addr::from_octets([2, 2, 2, 5]));
                assert_eq!(ips[4], Ipv4Addr::from_octets([2, 2, 2, 6]));
                ips[0] = Ipv4Addr::from_octets([4, 5, 6, 7]);
            }
        }
        assert_eq!(&bytes[12..16], [4, 5, 6, 7]);
    }

    #[test]
    fn not_enough_ips() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x11,
            0x00,
            0x00, 0x00,
            1, 4, 6, 8,
            0b0000_0_010, 64,
            0x00, 0x05,

            2, 2, 2, 2,
            2, 2, 2, 3,
            2, 2, 2, 4,
            2, 2, 2, 5,
        ][..];
        let r = ValidIgmpMembershipQuery::parse(bytes);
        assert!(matches!(r, Err(ingot::types::ParseError::TooSmall)));
    }

    #[test]
    fn extra_payload() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x11,
            0x00,
            0x00, 0x00,
            1, 1, 1, 1,
            0b0000_0_010, 64,
            0x00, 0x03,

            2, 2, 2, 2,
            2, 2, 2, 3,
            2, 2, 2, 4,
            1, 2, 3, 4, 5 // bonus data
        ][..];
        let (_r, _, rest) = ValidIgmpMembershipQuery::parse(bytes).unwrap();
        assert_eq!(rest, &[1, 2, 3, 4, 5]);
    }
}
