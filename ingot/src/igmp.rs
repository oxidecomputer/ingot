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
    use crate::types::{Emit, Header, HeaderParse};
    use ingot_types::HeaderLen;

    impl IgmpV3GroupRecord {
        fn bytes_len(&self) -> usize {
            8 + self.source_addrs.len() * 4 + self.auxiliary_data.len()
        }
    }

    impl IgmpV3MembershipReport {
        fn bytes_len(&self) -> usize {
            8 + self.group_records.iter().map(|r| r.bytes_len()).sum::<usize>()
        }
    }

    fn compute_checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in bytes.chunks(2) {
            let word = match chunk {
                [a, b] => ((*a as u16) << 8) | (*b as u16),
                [a] => (*a as u16) << 8,
                _ => unreachable!(),
            };
            sum = sum.wrapping_add(word as u32);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

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

    #[test]
    fn generate_v3_membership_report() {
        let igmp_default = IgmpV3MembershipReport {
            ty: IgmpMessageType::V3_MEMBERSHIP_REPORT,
            ..Default::default()
        };
        let bytes = igmp_default.emit_vec();
        assert_eq!(bytes.len(), igmp_default.bytes_len());

        let igmp_with_group_addrs = IgmpV3MembershipReport {
            ty: IgmpMessageType::V3_MEMBERSHIP_REPORT,
            group_records: Repeated::new(vec![
                IgmpV3GroupRecord {
                    record_type: IgmpV3RecordType::MODE_IS_INCLUDE,
                    aux_data_len: 0,
                    num_sources: 0,
                    multicast_addr: Ipv4Addr::from_octets([239, 1, 2, 3]),
                    source_addrs: Vec::new(),
                    auxiliary_data: Vec::new(),
                },
                IgmpV3GroupRecord {
                    record_type: IgmpV3RecordType::MODE_IS_EXCLUDE,
                    aux_data_len: 0,
                    num_sources: 0,
                    multicast_addr: Ipv4Addr::from_octets([239, 1, 2, 4]),
                    source_addrs: Vec::new(),
                    auxiliary_data: Vec::new(),
                },
            ]),
            ..Default::default()
        };

        for record in igmp_with_group_addrs.group_records.iter() {
            assert_eq!(record.bytes_len(), 8);
            assert!(record.multicast_addr.is_multicast());
        }

        let bytes = igmp_with_group_addrs.emit_vec();
        assert_eq!(bytes.len(), igmp_with_group_addrs.bytes_len());
    }

    #[test]
    fn generate_v3_membership_queries() {
        // Test case with specific resv/s/qrv values
        let query_with_resv = IgmpMembershipQuery {
            ty: IgmpMessageType::MEMBERSHIP_QUERY,
            max_resp: 100,
            group_address: Ipv4Addr::from_octets([239, 1, 2, 3]),
            s: 1,   // Suppress router-side processing
            qrv: 2, // Robustness Variable
            qqic: 125,
            num_sources: 2,
            source_addrs: vec![
                Ipv4Addr::from_octets([192, 168, 1, 10]),
                Ipv4Addr::from_octets([192, 168, 1, 11]),
            ],
            ..Default::default()
        };

        let bytes = query_with_resv.emit_vec();
        // Check the byte containing resv(4 bits)|s(1 bit)|qrv(3 bits)
        assert_eq!(bytes[8] & 0xf0, 0); // Upper 4 bits (resv) should be zero
        assert_eq!(bytes[8] & 0x08, 0x08); // Next bit (s) should be 1
        assert_eq!(bytes[8] & 0x07, 0x02); // Last 3 bits (qrv) should be 2

        // Test with different s/qrv combinations
        let query_variations = [
            (0, 7, 0x07), // s=0, qrv=7 -> 0000_0111
            (1, 7, 0x0f), // s=1, qrv=7 -> 0000_1111
            (0, 0, 0x00), // s=0, qrv=0 -> 0000_0000
            (1, 0, 0x08), // s=1, qrv=0 -> 0000_1000
        ];

        for (s, qrv, expected) in query_variations {
            let query = IgmpMembershipQuery {
                ty: IgmpMessageType::MEMBERSHIP_QUERY,
                max_resp: 100,
                group_address: Ipv4Addr::from_octets([239, 1, 2, 3]),
                s,
                qrv,
                qqic: 125,
                num_sources: 0,
                source_addrs: vec![],
                ..Default::default()
            };

            let bytes = query.emit_vec();
            assert_eq!(
                bytes[8], expected,
                "Failed for s={}, qrv={}, got {:08b}, expected {:08b}",
                s, qrv, bytes[8], expected
            );
        }
    }

    #[test]
    fn generate_v2_membership_report() {
        let report = IgmpV2MembershipReport {
            ty: IgmpMessageType::V2_MEMBERSHIP_REPORT,
            max_resp: 0, // Should be zero in transmission
            checksum: 0, // Will be computed by higher layer
            group_address: Ipv4Addr::from_octets([239, 1, 2, 3]), // Valid multicast address
        };

        let bytes = report.emit_vec();
        assert_eq!(bytes.len(), 8); // V2 messages are fixed size
        assert_eq!(bytes[0], 0x16); // V2 report type
        assert_eq!(bytes[4..8], [239, 1, 2, 3]); // Group address
    }

    #[test]
    fn generate_invalid_mcast_v2_membership_report() {
        let report = IgmpV2MembershipReport {
            ty: IgmpMessageType::V2_MEMBERSHIP_REPORT,
            group_address: Ipv4Addr::from_octets([192, 0, 0, 1]), // Invalid multicast address
            ..Default::default()
        };

        assert!(!report.group_address.is_multicast());
    }

    #[test]
    fn generate_v2_leave_group() {
        let leave = IgmpV2LeaveGroup {
            ty: IgmpMessageType::V2_LEAVE_GROUP,
            group_address: Ipv4Addr::from_octets([239, 1, 2, 3]),
            ..Default::default()
        };

        let bytes = leave.emit_vec();
        assert_eq!(bytes.len(), 8); // V2 messages are fixed size
        assert_eq!(bytes[0], 0x17); // Leave group type
        assert_eq!(bytes[4..8], [239, 1, 2, 3]); // Group address
    }

    #[test]
    fn test_max_size_messages() {
        let max_sources = 100; // Use a reasonable maximum for testing
        let max_query = IgmpMembershipQuery {
            ty: IgmpMessageType::MEMBERSHIP_QUERY,
            max_resp: 100,
            checksum: 0,
            group_address: Ipv4Addr::from_octets([224, 0, 0, 1]),
            s: 1,
            qrv: 2,
            qqic: 125,
            num_sources: max_sources,
            source_addrs: vec![Ipv4Addr::UNSPECIFIED; max_sources as usize],
            ..Default::default()
        };

        let bytes = max_query.emit_vec();
        assert_eq!(bytes.len(), 12 + (max_sources as usize * 4));
    }

    #[test]
    fn test_round_trip_v3_membership_query() {
        let original_query = IgmpMembershipQuery {
            ty: IgmpMessageType::MEMBERSHIP_QUERY,
            max_resp: 100,
            group_address: Ipv4Addr::from_octets([224, 0, 0, 1]),
            s: 1,
            qrv: 2,
            qqic: 125,
            num_sources: 2,
            source_addrs: vec![
                Ipv4Addr::from_octets([192, 168, 1, 10]),
                Ipv4Addr::from_octets([192, 168, 1, 11]),
            ],
            ..Default::default()
        };

        let bytes = original_query.emit_vec();
        let (parsed_query, ..) =
            ValidIgmpMembershipQuery::parse(&*bytes).unwrap();

        assert_eq!(parsed_query.ty(), original_query.ty);
        assert_eq!(parsed_query.max_resp(), original_query.max_resp);
        assert_eq!(parsed_query.group_address(), original_query.group_address);
        assert_eq!(parsed_query.qrv(), original_query.qrv);
        assert_eq!(parsed_query.qqic(), original_query.qqic);
        assert_eq!(parsed_query.num_sources(), original_query.num_sources);
    }

    #[test]
    fn test_round_trip_v3_membership_report() {
        let original_report = IgmpV3MembershipReport {
            ty: IgmpMessageType::V3_MEMBERSHIP_REPORT,
            resv1: 0,
            checksum: 0,
            resv2: 0,
            num_group_records: 2,
            group_records: Repeated::new(vec![
                IgmpV3GroupRecord {
                    record_type: IgmpV3RecordType::MODE_IS_INCLUDE,
                    aux_data_len: 0,
                    num_sources: 0,
                    multicast_addr: Ipv4Addr::from_octets([1, 2, 3, 4]),
                    source_addrs: Vec::new(),
                    auxiliary_data: Vec::new(),
                },
                IgmpV3GroupRecord {
                    record_type: IgmpV3RecordType::MODE_IS_EXCLUDE,
                    aux_data_len: 0,
                    num_sources: 0,
                    multicast_addr: Ipv4Addr::from_octets([5, 6, 7, 8]),
                    source_addrs: Vec::new(),
                    auxiliary_data: Vec::new(),
                },
            ]),
        };

        let bytes = original_report.emit_vec();
        let (parsed_report, ..) =
            ValidIgmpV3MembershipReport::parse(&*bytes).unwrap();

        assert_eq!(parsed_report.ty(), original_report.ty);
        assert_eq!(parsed_report.resv1(), original_report.resv1);
        assert_eq!(parsed_report.checksum(), original_report.checksum);
        assert_eq!(parsed_report.resv2(), original_report.resv2);
        assert_eq!(
            parsed_report.num_group_records(),
            original_report.num_group_records
        );

        let original_records = original_report.group_records.iter();
        let original_records_plen =
            original_records.map(|r| r.bytes_len()).sum::<usize>();
        let parsed_records_plen =
            parsed_report.group_records_ref().packet_length();
        assert_eq!(original_records_plen, parsed_records_plen);
    }

    #[test]
    fn test_checksum_verification() {
        let mut query = IgmpMembershipQuery {
            ty: IgmpMessageType::MEMBERSHIP_QUERY,
            max_resp: 100,
            checksum: 0, // Initially zero
            group_address: Ipv4Addr::from_octets([224, 0, 0, 1]),
            s: 1,
            qrv: 2,
            qqic: 125,
            num_sources: 1,
            source_addrs: vec![Ipv4Addr::from_octets([192, 168, 1, 1])],
            ..Default::default()
        };

        let mut bytes = query.emit_vec();
        let computed_checksum = compute_checksum(&bytes);
        query.checksum = computed_checksum;

        // Re-emit with correct checksum
        bytes = query.emit_vec();
        assert_eq!(compute_checksum(&bytes), 0);
    }
}
