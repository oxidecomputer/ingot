// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast Listener Discovery, versions 1 ([RFC2710]) and 2 ([RFC3810]).
//!
//! MLD messages are ICMPv6 messages: each header below begins with the
//! ICMPv6 type, code, and checksum fields, and the message body follows in
//! place of the ICMPv6 `rest_of_hdr` field.
//!
//! Version is not always recoverable from the ICMPv6 type: MLDv1 and MLDv2
//! Queries both use type 130 and are separated by message length instead.
//! See [`MldV1`] for that rule.
//!
//! MLDv2 Queries and Reports may carry data beyond the fields listed here
//! ([RFC3810], §5.1.12 and §5.2.11). Callers must fold those bytes into
//! the ICMPv6 checksum but otherwise ignore them, as this module computes no
//! checksums itself. Both messages return them as the parse remainder, since
//! a Report's `records` are bounded by `num_records` rather than read to
//! buffer exhaustion.
//!
//! [RFC2710]: https://datatracker.ietf.org/doc/html/rfc2710
//! [RFC3810]: https://datatracker.ietf.org/doc/html/rfc3810

use crate::icmp::IcmpV6Type;
use ingot_macros::Ingot;
use ingot_types::{
    primitives::*, util::Repeated, Ipv6Addr, MulticastIpv6Addr, Vec,
};

/// See [RFC2710, §3].
///
/// The Query (type 130), Report (131), and Done (132) messages of MLDv1
/// share this layout. Build one with [`MldV1::general_query`],
/// [`MldV1::address_specific_query`], [`MldV1::report`], or [`MldV1::done`].
/// There is deliberately no `Default`, since no ICMPv6 type is a sensible
/// default and zero is RESERVED.
///
/// ICMPv6 type alone does not identify the version. Types 131 and 132 are
/// MLDv1 only, but both MLDv1 and MLDv2 Queries use type 130, and are told
/// apart by message length ([RFC3810, §8.1]): 24 octets is MLDv1, 28 or more
/// is MLDv2, and any other length must be silently ignored. Parsing a type
/// 130 message as [`MldV2MulticastListenerQuery`] therefore yields
/// `TooSmall` for every MLDv1 Query, which is a prompt to retry as `MldV1`
/// rather than evidence that the packet is malformed.
///
/// [RFC2710, §3]: https://datatracker.ietf.org/doc/html/rfc2710#section-3
/// [RFC3810, §8.1]: https://datatracker.ietf.org/doc/html/rfc3810#section-8.1
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct MldV1 {
    #[ingot(zerocopy)]
    pub ty: IcmpV6Type,
    pub code: u8,
    pub checksum: u16be,
    /// Milliseconds. Set only in Query messages, and zero elsewhere.
    pub max_response_delay: u16be,
    resv: u16be,
    #[ingot(zerocopy)]
    pub group_addr: Ipv6Addr,
}

impl MldV1 {
    /// Build a General Query, with `max_response_delay` in milliseconds.
    ///
    /// The Multicast Address field of a General Query is the unspecified
    /// address, per [RFC2710, §3.6], so no address is taken here. Asking after
    /// one group is [`MldV1::address_specific_query`].
    ///
    /// [RFC2710, §3.6]: https://datatracker.ietf.org/doc/html/rfc2710#section-3.6
    pub fn general_query(max_response_delay: u16) -> Self {
        Self {
            ty: IcmpV6Type::MULTICAST_LISTENER_QUERY,
            code: 0,
            checksum: 0,
            max_response_delay,
            resv: 0,
            group_addr: Ipv6Addr::UNSPECIFIED,
        }
    }

    /// Build a Multicast-Address-Specific Query for `group_addr`, with
    /// `max_response_delay` in milliseconds.
    pub fn address_specific_query(
        max_response_delay: u16,
        group_addr: MulticastIpv6Addr,
    ) -> Self {
        Self {
            ty: IcmpV6Type::MULTICAST_LISTENER_QUERY,
            code: 0,
            checksum: 0,
            max_response_delay,
            resv: 0,
            group_addr: group_addr.addr(),
        }
    }

    /// Build a Report for `group_addr`.
    pub fn report(group_addr: MulticastIpv6Addr) -> Self {
        Self {
            ty: IcmpV6Type::V1_MULTICAST_LISTENER_REPORT,
            code: 0,
            checksum: 0,
            max_response_delay: 0,
            resv: 0,
            group_addr: group_addr.addr(),
        }
    }

    /// Build a Done for `group_addr`.
    pub fn done(group_addr: MulticastIpv6Addr) -> Self {
        Self {
            ty: IcmpV6Type::V1_MULTICAST_LISTENER_DONE,
            code: 0,
            checksum: 0,
            max_response_delay: 0,
            resv: 0,
            group_addr: group_addr.addr(),
        }
    }

    /// Check the address-class constraints of [RFC2710, §3].
    ///
    /// A Query carries the unspecified address (General) or the queried
    /// group.
    ///
    /// A Report or Done always names a group.
    ///
    /// Reserved fields are ignored by receivers per the RFC and
    /// deliberately not checked.
    ///
    /// [RFC2710, §3]: https://datatracker.ietf.org/doc/html/rfc2710#section-3
    pub fn validate(&self) -> Result<(), MldValidationError> {
        let group_ok = match self.ty {
            IcmpV6Type::MULTICAST_LISTENER_QUERY => {
                self.group_addr == Ipv6Addr::UNSPECIFIED
                    || self.group_addr.is_multicast()
            }
            IcmpV6Type::V1_MULTICAST_LISTENER_REPORT
            | IcmpV6Type::V1_MULTICAST_LISTENER_DONE => {
                self.group_addr.is_multicast()
            }
            _ => return Err(MldValidationError::WrongType),
        };

        ensure(group_ok, MldValidationError::GroupNotMulticast)
    }
}

/// See [RFC3810, §5.1].
///
/// [RFC3810, §5.1]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct MldV2MulticastListenerQuery {
    #[ingot(zerocopy, default = IcmpV6Type::MULTICAST_LISTENER_QUERY)]
    pub ty: IcmpV6Type,
    pub code: u8,
    pub checksum: u16be,
    pub max_resp_code: u16be,
    resv1: u16be,
    #[ingot(zerocopy, default = Ipv6Addr::UNSPECIFIED)]
    pub group_addr: Ipv6Addr,
    resv2: u4, // padding

    pub s: u1,
    pub qrv: u3,
    pub qqic: u8,
    /// The number of entries in `source_addrs`.
    pub num_sources: u16be,

    #[ingot(zerocopy, var_len = "num_sources.get()")]
    pub source_addrs: Vec<Ipv6Addr>,
}

/// Decode a Max Resp Code into a Maximum Response Delay in milliseconds, per
/// [RFC3810, §5.1.3].
///
/// Codes below 32768 are the delay itself. Above that, the code is a
/// floating-point form, `1 | exp(3) | mant(12)`, worth up to 8_387_584 ms and
/// is returned as a [`u32`].
///
/// [RFC3810, §5.1.3]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1.3
pub fn max_response_delay_ms(max_resp_code: u16) -> u32 {
    match max_resp_code {
        code if code < 0x8000 => code.into(),
        code => {
            let exp = u32::from((code >> 12) & 0x7);
            let mant = u32::from(code & 0x0fff);
            (mant | 0x1000) << (exp + 3)
        }
    }
}

/// Decode a QQIC into a Querier's Query Interval in seconds, per
/// [RFC3810, §5.1.9].
///
/// Codes below 128 are the interval itself. Above that, the code is the same
/// floating-point form one octet wide, `1 | exp(3) | mant(4)`.
///
/// [RFC3810, §5.1.9]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1.9
pub fn querier_query_interval_secs(qqic: u8) -> u32 {
    match qqic {
        code if code < 0x80 => code.into(),
        code => {
            let exp = u32::from((code >> 4) & 0x7);
            let mant = u32::from(code & 0x0f);
            (mant | 0x10) << (exp + 3)
        }
    }
}

/// A source address must be unicast (RFC3810, §5.1.11 and §5.2.9), which
/// excludes the unspecified address: RFC4291, §2.5.2 defines `::` as marking
/// the absence of an address rather than naming one. Loopback is a unicast
/// address and deliberately passes and rejecting it is forwarding policy (not
/// message validity).
fn is_unicast_source(addr: &Ipv6Addr) -> bool {
    *addr != Ipv6Addr::UNSPECIFIED && addr.is_unicast()
}

/// The error returned when an MLD message violates the class constraints of
/// its RFC.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MldValidationError {
    /// The ICMPv6 type is not the expected MLD message type.
    WrongType,
    /// A group or record address is required to be multicast and is not.
    GroupNotMulticast,
    /// A General Query contains one or more source addresses.
    GeneralQueryHasSources,
    /// A source address is required to be unicast and is not.
    SourceNotUnicast,
}

impl core::error::Error for MldValidationError {}

impl core::fmt::Display for MldValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::WrongType => "ICMPv6 type is not the expected MLD type",
            Self::GroupNotMulticast => "group address is not multicast",
            Self::GeneralQueryHasSources => {
                "General Query contains source addresses"
            }
            Self::SourceNotUnicast => "source address is not unicast",
        })
    }
}

/// Lift a checked condition into the validation error monad: `Ok(())` when
/// `cond` holds, `err` otherwise. Sequenced with `?`.
const fn ensure(
    cond: bool,
    err: MldValidationError,
) -> Result<(), MldValidationError> {
    if cond {
        Ok(())
    } else {
        Err(err)
    }
}

impl MldV2MulticastListenerQuery {
    /// Check the class constraints of [RFC3810, §5.1].
    ///
    /// The group is the unspecified address for a General Query or a
    /// multicast address otherwise ([§5.1.5]), and every source is unicast
    /// ([§5.1.11]). Reserved fields are ignored by receivers per [§5.1.4] and
    /// deliberately not checked.
    ///
    /// [RFC3810, §5.1]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1
    /// [§5.1.5]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1.5
    /// [§5.1.11]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1.11
    /// [§5.1.4]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.1.4
    pub fn validate(&self) -> Result<(), MldValidationError> {
        ensure(
            matches!(self.ty, IcmpV6Type::MULTICAST_LISTENER_QUERY),
            MldValidationError::WrongType,
        )?;
        if self.group_addr == Ipv6Addr::UNSPECIFIED {
            ensure(
                self.source_addrs.is_empty(),
                MldValidationError::GeneralQueryHasSources,
            )
        } else {
            ensure(
                self.group_addr.is_multicast(),
                MldValidationError::GroupNotMulticast,
            )
        }?;
        ensure(
            self.source_addrs.iter().all(is_unicast_source),
            MldValidationError::SourceNotUnicast,
        )
    }
}

/// See [RFC3810, §5.2].
///
/// An MLDv2 Report is carried by ICMPv6 type 143, which is assigned by
/// RFC3810 rather than by [RFC2710].
///
/// [RFC3810, §5.2]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2
/// [RFC2710]: https://datatracker.ietf.org/doc/html/rfc2710
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct MldV2MulticastListenerReport {
    #[ingot(zerocopy, default = IcmpV6Type::V2_MULTICAST_LISTENER_REPORT)]
    pub ty: IcmpV6Type,
    /// Named `Reserved` by RFC3810, §5.2.1, and sent as zero.
    pub code: u8,
    pub checksum: u16be,
    resv: u16be,
    /// The number of entries in `records`.
    pub num_records: u16be,
    #[ingot(subparse(count = "num_records.get()"))]
    pub records: Repeated<MldV2AddressRecord>,
}

ingot_types::zerocopy_type!(
    /// See [RFC3810, §5.2.12].
    ///
    /// [RFC3810, §5.2.12]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.12
    #[derive(Default)]
    pub struct MldV2RecordType(pub u8)
);

impl MldV2RecordType {
    pub const MODE_IS_INCLUDE: Self = Self(1);
    pub const MODE_IS_EXCLUDE: Self = Self(2);
    pub const CHANGE_TO_INCLUDE_MODE: Self = Self(3);
    pub const CHANGE_TO_EXCLUDE_MODE: Self = Self(4);
    pub const ALLOW_NEW_SOURCES: Self = Self(5);
    pub const BLOCK_OLD_SOURCES: Self = Self(6);
}

/// See [RFC3810, §5.2.4].
///
/// [RFC3810, §5.2.4]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.4
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct MldV2AddressRecord {
    #[ingot(zerocopy)]
    pub record_type: MldV2RecordType,
    /// Length of `auxiliary_data` in units of 32-bit words, per
    /// [RFC3810, §5.2.6].
    ///
    /// [RFC3810, §5.2.6]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.6
    pub aux_data_len: u8,
    /// The number of entries in `source_addrs`.
    pub num_sources: u16be,
    #[ingot(zerocopy)]
    pub multicast_addr: Ipv6Addr,

    #[ingot(zerocopy, var_len = "num_sources.get()")]
    pub source_addrs: Vec<Ipv6Addr>,
    #[ingot(var_len = "(aux_data_len as usize) * 4")]
    pub auxiliary_data: Vec<u8>,
}

impl MldV2AddressRecord {
    /// Check the class constraints of [RFC3810, §5.2.4].
    ///
    /// The record names a multicast group ([§5.2.8]) with unicast sources
    /// ([§5.2.9]). Unrecognised record types must be silently ignored per
    /// [§5.2.12], so `record_type` is deliberately not checked.
    ///
    /// [RFC3810, §5.2.4]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.4
    /// [§5.2.8]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.8
    /// [§5.2.9]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.9
    /// [§5.2.12]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2.12
    pub fn validate(&self) -> Result<(), MldValidationError> {
        ensure(
            self.multicast_addr.is_multicast(),
            MldValidationError::GroupNotMulticast,
        )?;
        ensure(
            self.source_addrs.iter().all(is_unicast_source),
            MldValidationError::SourceNotUnicast,
        )
    }
}

impl MldV2MulticastListenerReport {
    /// Check the class constraints of [RFC3810, §5.2], across every record.
    ///
    /// [RFC3810, §5.2]: https://datatracker.ietf.org/doc/html/rfc3810#section-5.2
    pub fn validate(&self) -> Result<(), MldValidationError> {
        ensure(
            matches!(self.ty, IcmpV6Type::V2_MULTICAST_LISTENER_REPORT),
            MldValidationError::WrongType,
        )?;
        self.records.iter().try_for_each(MldV2AddressRecord::validate)
    }
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)]
mod tests {
    use super::*;
    use crate::types::{Emit, HeaderParse};
    use ingot_types::HeaderLen;

    impl MldV2AddressRecord {
        fn bytes_len(&self) -> usize {
            20 + self.source_addrs.len() * 16 + self.auxiliary_data.len()
        }
    }

    impl MldV2MulticastListenerReport {
        fn bytes_len(&self) -> usize {
            8 + self.records.iter().map(|r| r.bytes_len()).sum::<usize>()
        }
    }

    /// `ff02::1`, the all-nodes link-local multicast address.
    const ALL_NODES: Ipv6Addr =
        Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 1]);

    /// [`ALL_NODES`], refined at compile time.
    const ALL_NODES_GROUP: MulticastIpv6Addr =
        MulticastIpv6Addr::new_unchecked(ALL_NODES);

    /// `ff02::16`, the address MLDv2 Reports are sent to per RFC3810,
    /// §5.2.14.
    const ALL_MLDV2_ROUTERS: Ipv6Addr =
        Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 0x16]);

    /// `fe80::1`, standing in for the link-local source of an MLD message.
    const LINK_LOCAL: Ipv6Addr =
        Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);

    fn source(last: u16) -> Ipv6Addr {
        Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, last])
    }

    /// The standard ICMPv6 checksum, taken over the IPv6 pseudo-header of
    /// RFC8200, §8.1 followed by the MLD message itself.
    ///
    /// Unlike IGMP, which checksums the message alone, MLD inherits the
    /// ICMPv6 rule that the pseudo-header participates, so a caller cannot
    /// verify an MLD message without the enclosing IPv6 addresses.
    fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, msg: &[u8]) -> u16 {
        const ICMPV6_NEXT_HEADER: u8 = 58;

        // Folded over the chained iterator rather than a collected buffer, so
        // the pseudo-header is never materialised. The carried `Option` holds
        // a high byte awaiting its pair.
        let (sum, rest) = src
            .octets()
            .into_iter()
            .chain(dst.octets())
            .chain((msg.len() as u32).to_be_bytes())
            .chain([0, 0, 0, ICMPV6_NEXT_HEADER])
            .chain(msg.iter().copied())
            .fold((0u32, None), |(sum, rest), byte| match rest {
                None => (sum, Some(byte)),
                Some(high) => {
                    (sum + u32::from(u16::from_be_bytes([high, byte])), None)
                }
            });

        let sum = match rest {
            None => sum,
            Some(high) => sum + u32::from(u16::from_be_bytes([high, 0])),
        };

        // Two folds always suffice: the first cannot exceed 0x1fffe, so the
        // second cannot carry again.
        let sum = (sum & 0xffff) + (sum >> 16);
        let sum = (sum & 0xffff) + (sum >> 16);

        !(sum as u16)
    }

    #[test]
    fn parse() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x82,
            0x00,
            0x00, 0x00,
            0x27, 0x10,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            0b0000_1_010, 64,
            0x00, 0x02,

            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0a,

            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0b,
        ][..];
        let (mld, ..) = ValidMldV2MulticastListenerQuery::parse(bytes).unwrap();
        assert_eq!(mld.ty(), IcmpV6Type::MULTICAST_LISTENER_QUERY);
        assert_eq!(mld.code(), 0);
        assert_eq!(mld.checksum(), 0);
        assert_eq!(mld.max_resp_code(), 10_000);
        assert_eq!(mld.group_addr(), ALL_NODES);
        assert_eq!(mld.s(), 1);
        assert_eq!(mld.qrv(), 0b10);
        assert_eq!(mld.qqic(), 64);
        assert_eq!(mld.num_sources(), 2);

        match mld.source_addrs_ref() {
            ingot_types::FieldRef::Repr(_a) => todo!("owned"),
            ingot_types::FieldRef::Raw(ips) => {
                assert_eq!(ips.len(), 2);
                assert_eq!(ips[0], source(0x0a));
                assert_eq!(ips[1], source(0x0b));
            }
        }
    }

    #[test]
    fn parse_mut() {
        #[rustfmt::skip]
        let bytes: &mut [u8] = &mut [
            0x82,
            0x00,
            0x00, 0x00,
            0x27, 0x10,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            0b0000_1_010, 64,
            0x00, 0x02,

            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0a,

            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0b,
        ][..];
        let (mut mld, ..) =
            ValidMldV2MulticastListenerQuery::parse(&mut bytes[..]).unwrap();

        match mld.source_addrs_mut() {
            ingot_types::FieldMut::Repr(_a) => todo!("owned"),
            ingot_types::FieldMut::Raw(ips) => {
                assert_eq!(ips.len(), 2);
                assert_eq!(ips[0], source(0x0a));
                assert_eq!(ips[1], source(0x0b));
                ips[0] = ALL_NODES;
            }
        }
        assert_eq!(&bytes[28..44], &ALL_NODES.octets()[..]);
    }

    #[test]
    fn extra_payload() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x82,
            0x00,
            0x00, 0x00,
            0x27, 0x10,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            0b0000_1_010, 64,
            0x00, 0x01,

            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0a,

            1, 2, 3, 4, 5 // bonus data
        ][..];
        let (_r, _, rest) =
            ValidMldV2MulticastListenerQuery::parse(bytes).unwrap();
        assert_eq!(rest, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn parse_v1() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x84,
            0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,
        ][..];
        let (mld, _, rest) = ValidMldV1::parse(bytes).unwrap();
        assert_eq!(mld.ty(), IcmpV6Type::V1_MULTICAST_LISTENER_DONE);
        assert_eq!(mld.max_response_delay(), 0);
        assert_eq!(mld.group_addr(), ALL_NODES);
        assert!(rest.is_empty());
    }

    #[test]
    fn generate_v1_report() {
        let report = MldV1::report(ALL_NODES_GROUP);

        let bytes = report.emit_vec();
        assert_eq!(bytes.len(), 24); // MLDv1 messages are fixed size
        assert_eq!(bytes[0], 131);
        assert_eq!(bytes[8..24], ALL_NODES.octets());
        assert!(report.group_addr.is_multicast());
    }

    #[test]
    fn generate_v2_membership_queries() {
        let query_with_resv = MldV2MulticastListenerQuery {
            max_resp_code: 10_000,
            group_addr: ALL_NODES,
            s: 1,   // Suppress router-side processing
            qrv: 2, // Robustness Variable
            qqic: 125,
            num_sources: 2,
            source_addrs: vec![source(0x0a), source(0x0b)],
            ..Default::default()
        };

        let bytes = query_with_resv.emit_vec();
        assert_eq!(bytes.len(), 28 + 2 * 16);
        // Check the byte containing resv(4 bits)|s(1 bit)|qrv(3 bits)
        assert_eq!(bytes[24] & 0xf0, 0); // Upper 4 bits (resv) should be zero
        assert_eq!(bytes[24] & 0x08, 0x08); // Next bit (s) should be 1
        assert_eq!(bytes[24] & 0x07, 0x02); // Last 3 bits (qrv) should be 2

        let query_variations = [
            (0, 7, 0x07), // s=0, qrv=7 -> 0000_0111
            (1, 7, 0x0f), // s=1, qrv=7 -> 0000_1111
            (0, 0, 0x00), // s=0, qrv=0 -> 0000_0000
            (1, 0, 0x08), // s=1, qrv=0 -> 0000_1000
        ];

        for (s, qrv, expected) in query_variations {
            let query = MldV2MulticastListenerQuery {
                max_resp_code: 10_000,
                group_addr: ALL_NODES,
                s,
                qrv,
                qqic: 125,
                ..Default::default()
            };

            let bytes = query.emit_vec();
            assert_eq!(
                bytes[24], expected,
                "Failed for s={}, qrv={}, got {:08b}, expected {:08b}",
                s, qrv, bytes[24], expected
            );
        }
    }

    #[test]
    fn generate_v2_membership_report() {
        let report_default = MldV2MulticastListenerReport::default();
        let bytes = report_default.emit_vec();
        assert_eq!(bytes.len(), report_default.bytes_len());
        assert_eq!(bytes[0], 143);

        let report_with_records = MldV2MulticastListenerReport {
            num_records: 2,
            records: Repeated::new(vec![
                MldV2AddressRecord {
                    record_type: MldV2RecordType::MODE_IS_INCLUDE,
                    aux_data_len: 0,
                    num_sources: 1,
                    multicast_addr: ALL_NODES,
                    source_addrs: vec![source(0x0a)],
                    auxiliary_data: Vec::new(),
                },
                MldV2AddressRecord {
                    record_type: MldV2RecordType::BLOCK_OLD_SOURCES,
                    aux_data_len: 0,
                    num_sources: 0,
                    multicast_addr: ALL_NODES,
                    source_addrs: Vec::new(),
                    auxiliary_data: Vec::new(),
                },
            ]),
            ..Default::default()
        };

        for record in report_with_records.records.iter() {
            assert!(record.multicast_addr.is_multicast());
        }

        let bytes = report_with_records.emit_vec();
        assert_eq!(bytes.len(), report_with_records.bytes_len());
        assert_eq!(bytes.len(), 8 + (20 + 16) + 20);
    }

    #[test]
    fn round_trip_v2_membership_query() {
        let original_query = MldV2MulticastListenerQuery {
            max_resp_code: 10_000,
            group_addr: ALL_NODES,
            s: 1,
            qrv: 2,
            qqic: 125,
            num_sources: 2,
            source_addrs: vec![source(0x0a), source(0x0b)],
            ..Default::default()
        };

        let bytes = original_query.emit_vec();
        let (parsed_query, ..) =
            ValidMldV2MulticastListenerQuery::parse(&*bytes).unwrap();

        assert_eq!(parsed_query.ty(), original_query.ty);
        assert_eq!(parsed_query.max_resp_code(), original_query.max_resp_code);
        assert_eq!(parsed_query.group_addr(), original_query.group_addr);
        assert_eq!(parsed_query.s(), original_query.s);
        assert_eq!(parsed_query.qrv(), original_query.qrv);
        assert_eq!(parsed_query.qqic(), original_query.qqic);
        assert_eq!(parsed_query.num_sources(), original_query.num_sources);
    }

    #[test]
    fn round_trip_v1() {
        let original = MldV1::address_specific_query(1000, ALL_NODES_GROUP);

        let bytes = original.emit_vec();
        let (parsed, ..) = ValidMldV1::parse(&*bytes).unwrap();

        assert_eq!(parsed.ty(), original.ty);
        assert_eq!(parsed.code(), original.code);
        assert_eq!(parsed.checksum(), original.checksum);
        assert_eq!(parsed.max_response_delay(), original.max_response_delay);
        assert_eq!(parsed.group_addr(), original.group_addr);
    }

    #[test]
    fn round_trip_v2_membership_report() {
        let original_report = MldV2MulticastListenerReport {
            ty: IcmpV6Type::V2_MULTICAST_LISTENER_REPORT,
            code: 0,
            checksum: 0,
            resv: 0,
            num_records: 2,
            records: Repeated::new(vec![
                MldV2AddressRecord {
                    record_type: MldV2RecordType::CHANGE_TO_INCLUDE_MODE,
                    aux_data_len: 0,
                    num_sources: 2,
                    multicast_addr: ALL_NODES,
                    source_addrs: vec![source(0x0a), source(0x0b)],
                    auxiliary_data: Vec::new(),
                },
                MldV2AddressRecord {
                    record_type: MldV2RecordType::ALLOW_NEW_SOURCES,
                    aux_data_len: 0,
                    num_sources: 0,
                    multicast_addr: ALL_NODES,
                    source_addrs: Vec::new(),
                    auxiliary_data: Vec::new(),
                },
            ]),
        };

        let bytes = original_report.emit_vec();
        let (parsed_report, ..) =
            ValidMldV2MulticastListenerReport::parse(&*bytes).unwrap();

        assert_eq!(parsed_report.ty(), original_report.ty);
        assert_eq!(parsed_report.code(), original_report.code);
        assert_eq!(parsed_report.checksum(), original_report.checksum);
        assert_eq!(parsed_report.num_records(), original_report.num_records);

        let original_records = original_report.records.iter();
        let original_records_plen =
            original_records.map(|r| r.bytes_len()).sum::<usize>();
        let parsed_records_plen = parsed_report.records_ref().packet_length();
        assert_eq!(original_records_plen, parsed_records_plen);
    }

    #[test]
    fn address_record_aux_data_is_counted_in_words() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x01,
            0x02, // two 32-bit words of auxiliary data
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            1, 2, 3, 4,
            5, 6, 7, 8,
        ][..];
        let (record, _, rest) = ValidMldV2AddressRecord::parse(bytes).unwrap();
        assert_eq!(record.record_type(), MldV2RecordType::MODE_IS_INCLUDE);
        assert_eq!(record.aux_data_len(), 2);
        assert_eq!(record.num_sources(), 0);
        assert_eq!(record.multicast_addr(), ALL_NODES);
        assert_eq!(record.packet_length(), 28);
        assert!(rest.is_empty());

        // One word short of the advertised auxiliary data.
        let r = ValidMldV2AddressRecord::parse(&bytes[..24]);
        assert!(matches!(r, Err(ingot::types::ParseError::TooSmall)));
    }

    #[test]
    fn address_record_aux_data_round_trips() {
        let record = MldV2AddressRecord {
            record_type: MldV2RecordType::MODE_IS_EXCLUDE,
            aux_data_len: 2,
            num_sources: 1,
            multicast_addr: ALL_NODES,
            source_addrs: vec![source(0x0a)],
            auxiliary_data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let bytes = record.emit_vec();
        assert_eq!(bytes.len(), 20 + 16 + 8);
        // The length stays in words on the wire, not octets.
        assert_eq!(bytes[1], 2);
        assert_eq!(&bytes[36..], &[1, 2, 3, 4, 5, 6, 7, 8]);

        let (parsed, _, rest) =
            ValidMldV2AddressRecord::parse(&bytes[..]).unwrap();
        assert_eq!(parsed.aux_data_len(), 2);
        assert_eq!(parsed.num_sources(), 1);
        assert_eq!(parsed.packet_length(), 44);
        assert!(rest.is_empty());
    }

    #[test]
    fn report_records_with_aux_data_keep_their_boundaries() {
        let report = MldV2MulticastListenerReport {
            num_records: 2,
            records: Repeated::new(vec![
                MldV2AddressRecord {
                    record_type: MldV2RecordType::MODE_IS_INCLUDE,
                    aux_data_len: 1,
                    num_sources: 0,
                    multicast_addr: ALL_NODES,
                    source_addrs: Vec::new(),
                    auxiliary_data: vec![0xde, 0xad, 0xbe, 0xef],
                },
                MldV2AddressRecord {
                    record_type: MldV2RecordType::BLOCK_OLD_SOURCES,
                    aux_data_len: 0,
                    num_sources: 1,
                    multicast_addr: ALL_NODES,
                    source_addrs: vec![source(0x0b)],
                    auxiliary_data: Vec::new(),
                },
            ]),
            ..Default::default()
        };

        let bytes = report.emit_vec();
        assert_eq!(bytes.len(), 8 + (20 + 4) + (20 + 16));

        // Undercounting the auxiliary data would leave the second record
        // starting mid-field, so the total length is what pins the boundary.
        let (parsed, _, rest) =
            ValidMldV2MulticastListenerReport::parse(&bytes[..]).unwrap();
        assert_eq!(parsed.records_ref().packet_length(), 24 + 36);
        assert!(rest.is_empty());

        // At the top of the field's range: the full 255-word (1020-octet)
        // auxiliary payload must not shift where the second record starts.
        let report = MldV2MulticastListenerReport {
            num_records: 2,
            records: Repeated::new(vec![
                MldV2AddressRecord {
                    record_type: MldV2RecordType::MODE_IS_INCLUDE,
                    aux_data_len: 255,
                    num_sources: 0,
                    multicast_addr: ALL_NODES,
                    source_addrs: Vec::new(),
                    auxiliary_data: vec![0xab; 1020],
                },
                MldV2AddressRecord {
                    record_type: MldV2RecordType::BLOCK_OLD_SOURCES,
                    aux_data_len: 0,
                    num_sources: 1,
                    multicast_addr: ALL_NODES,
                    source_addrs: vec![source(0x0b)],
                    auxiliary_data: Vec::new(),
                },
            ]),
            ..Default::default()
        };
        let bytes = report.emit_vec();
        assert_eq!(bytes.len(), 8 + (20 + 1020) + (20 + 16));
        let (parsed, _, rest) =
            ValidMldV2MulticastListenerReport::parse(&bytes[..]).unwrap();
        assert_eq!(parsed.records_ref().packet_length(), 1040 + 36);
        assert!(rest.is_empty());
    }

    #[test]
    fn report_count_bounds_records_and_preserves_trailing_data() {
        let record = MldV2AddressRecord {
            record_type: MldV2RecordType::MODE_IS_INCLUDE,
            aux_data_len: 0,
            num_sources: 0,
            multicast_addr: ALL_NODES,
            source_addrs: Vec::new(),
            auxiliary_data: Vec::new(),
        };
        let report = MldV2MulticastListenerReport {
            num_records: 1,
            records: Repeated::new(vec![record.clone()]),
            ..Default::default()
        };
        let mut bytes = report.emit_vec();
        bytes.extend_from_slice(&[1, 2, 3]);

        let (parsed, _, rest) =
            ValidMldV2MulticastListenerReport::parse(&bytes[..]).unwrap();
        assert_eq!(parsed.records_ref().packet_length(), 20);
        assert_eq!(rest, &[1, 2, 3]);

        let overcounted = MldV2MulticastListenerReport {
            num_records: 1,
            records: Repeated::new(vec![record.clone(), record]),
            ..Default::default()
        };
        let bytes = overcounted.emit_vec();
        let (parsed, _, rest) =
            ValidMldV2MulticastListenerReport::parse(&bytes[..]).unwrap();
        assert_eq!(parsed.records_ref().packet_length(), 20);
        assert_eq!(rest.len(), 20);
    }

    #[test]
    fn report_count_rejects_missing_records() {
        let report = MldV2MulticastListenerReport {
            num_records: 1,
            records: Repeated::new(vec![]),
            ..Default::default()
        };

        assert!(matches!(
            ValidMldV2MulticastListenerReport::parse(&report.emit_vec()[..]),
            Err(ingot_types::ParseError::TooSmall)
        ));
    }

    #[test]
    fn query_reserved_bits_do_not_alias_s_and_qrv() {
        #[rustfmt::skip]
        let mut bytes: [u8; 28] = [
            0x82,
            0x00,
            0x00, 0x00,
            0x27, 0x10,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            0b1111_0_000, 64,
            0x00, 0x00,
        ];

        // A set reserved nibble must not be read as s or qrv.
        let (mld, ..) =
            ValidMldV2MulticastListenerQuery::parse(&bytes[..]).unwrap();
        assert_eq!(mld.s(), 0);
        assert_eq!(mld.qrv(), 0);

        // And the converse: saturated s and qrv must not read as reserved.
        bytes[24] = 0b0000_1_111;
        let (mld, ..) =
            ValidMldV2MulticastListenerQuery::parse(&bytes[..]).unwrap();
        assert_eq!(mld.s(), 1);
        assert_eq!(mld.qrv(), 7);
    }

    #[test]
    fn max_size_query() {
        let max_sources = 100;
        let query = MldV2MulticastListenerQuery {
            max_resp_code: 10_000,
            group_addr: ALL_NODES,
            s: 1,
            qrv: 2,
            qqic: 125,
            num_sources: max_sources,
            source_addrs: vec![Ipv6Addr::UNSPECIFIED; max_sources as usize],
            ..Default::default()
        };

        let bytes = query.emit_vec();
        assert_eq!(bytes.len(), 28 + (max_sources as usize * 16));
    }

    #[test]
    fn overclaimed_num_sources_is_rejected_cleanly() {
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x82,
            0x00,
            0x00, 0x00,
            0x27, 0x10,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            0b0000_1_010, 64,
            0xff, 0xff, // 65535 sources, none of which follow
        ][..];
        let r = ValidMldV2MulticastListenerQuery::parse(bytes);
        assert!(matches!(r, Err(ingot::types::ParseError::TooSmall)));

        // Boundary form of the same failure, where two sources claimed,
        // but one is supplied.
        #[rustfmt::skip]
        let bytes: &[u8] = &[
            0x82,
            0x00,
            0x00, 0x00,
            0x27, 0x10,
            0x00, 0x00,

            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,

            0b0000_1_010, 64,
            0x00, 0x02,

            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0a,
        ][..];
        let r = ValidMldV2MulticastListenerQuery::parse(bytes);
        assert!(matches!(r, Err(ingot::types::ParseError::TooSmall)));
    }

    #[test]
    fn max_resp_code_decodes_both_forms() {
        // Below 32768 the code is the delay verbatim.
        assert_eq!(max_response_delay_ms(0), 0);
        assert_eq!(max_response_delay_ms(10_000), 10_000);
        assert_eq!(max_response_delay_ms(32_767), 32_767);

        // The floating-point form is continuous across the boundary:
        // exp = 0, mant = 0 gives (0 | 0x1000) << 3.
        assert_eq!(max_response_delay_ms(0x8000), 32_768);

        // exp = 7, mant = 0xfff gives (0x1fff) << 10, the largest encodable.
        assert_eq!(max_response_delay_ms(0xffff), 8_387_584);

        // A worked middle case: exp = 3, mant = 0x123.
        assert_eq!(
            max_response_delay_ms(0b1_011_0001_0010_0011),
            (0x123 | 0x1000) << 6
        );
    }

    #[test]
    fn qqic_decodes_both_forms() {
        assert_eq!(querier_query_interval_secs(0), 0);
        assert_eq!(querier_query_interval_secs(125), 125);
        assert_eq!(querier_query_interval_secs(127), 127);

        // Continuous at the boundary: exp = 0, mant = 0 gives (0x10) << 3.
        assert_eq!(querier_query_interval_secs(0x80), 128);

        // exp = 7, mant = 0xf gives 0x1f << 10.
        assert_eq!(querier_query_interval_secs(0xff), 31_744);

        // A worked middle case: exp = 2, mant = 0x5.
        assert_eq!(
            querier_query_interval_secs(0b1_010_0101),
            (0x5 | 0x10) << 5
        );
    }

    #[test]
    fn checksum_verification() {
        let mut report = MldV2MulticastListenerReport {
            num_records: 1,
            records: Repeated::new(vec![MldV2AddressRecord {
                record_type: MldV2RecordType::CHANGE_TO_EXCLUDE_MODE,
                aux_data_len: 0,
                num_sources: 1,
                multicast_addr: ALL_NODES,
                source_addrs: vec![source(0x0a)],
                auxiliary_data: Vec::new(),
            }]),
            ..Default::default()
        };

        let bytes = report.emit_vec();
        report.checksum =
            icmpv6_checksum(LINK_LOCAL, ALL_MLDV2_ROUTERS, &bytes);

        let bytes = report.emit_vec();
        assert_eq!(icmpv6_checksum(LINK_LOCAL, ALL_MLDV2_ROUTERS, &bytes), 0);

        // The pseudo-header participates, meaning that the same bytes under a
        // different source address must not verify.
        assert_ne!(icmpv6_checksum(ALL_NODES, ALL_MLDV2_ROUTERS, &bytes), 0);
    }

    #[test]
    fn validate_checks_address_classes() {
        assert_eq!(MldV1::general_query(1000).validate(), Ok(()));
        assert_eq!(
            MldV1::address_specific_query(1000, ALL_NODES_GROUP).validate(),
            Ok(())
        );
        assert_eq!(MldV1::report(ALL_NODES_GROUP).validate(), Ok(()));
        assert_eq!(MldV1::done(ALL_NODES_GROUP).validate(), Ok(()));

        let mut bad = MldV1::report(ALL_NODES_GROUP);
        bad.ty = IcmpV6Type::RESERVED_INFO;
        assert_eq!(bad.validate(), Err(MldValidationError::WrongType));

        // A Report must name a group (the unspecified address only passes
        // for a Query).
        let mut bad = MldV1::report(ALL_NODES_GROUP);
        bad.group_addr = Ipv6Addr::UNSPECIFIED;
        assert_eq!(bad.validate(), Err(MldValidationError::GroupNotMulticast));

        // The v2 Query default is a General Query and passes, while a multicast
        // source does not.
        assert_eq!(MldV2MulticastListenerQuery::default().validate(), Ok(()));
        let bad = MldV2MulticastListenerQuery {
            group_addr: ALL_NODES,
            num_sources: 1,
            source_addrs: vec![ALL_NODES],
            ..Default::default()
        };
        assert_eq!(bad.validate(), Err(MldValidationError::SourceNotUnicast));

        // `::` is not a unicast address (RFC4291, §2.5.2), so it cannot be
        // a source. Loopback is unicast and passes, since rejecting it is
        // forwarding policy rather than message validity.
        let bad = MldV2MulticastListenerQuery {
            group_addr: ALL_NODES,
            num_sources: 1,
            source_addrs: vec![Ipv6Addr::UNSPECIFIED],
            ..Default::default()
        };
        assert_eq!(bad.validate(), Err(MldValidationError::SourceNotUnicast));

        let bad = MldV2MulticastListenerQuery {
            num_sources: 1,
            source_addrs: vec![source(0x0a)],
            ..Default::default()
        };
        assert_eq!(
            bad.validate(),
            Err(MldValidationError::GeneralQueryHasSources)
        );

        let lo = MldV2MulticastListenerQuery {
            group_addr: ALL_NODES,
            num_sources: 1,
            source_addrs: vec![Ipv6Addr::LOCALHOST],
            ..Default::default()
        };
        assert_eq!(lo.validate(), Ok(()));

        // An unknown record type is not an error: receivers must silently
        // ignore it, so rejecting one here would violate the RFC.
        let odd_record = MldV2AddressRecord {
            record_type: MldV2RecordType(200),
            aux_data_len: 0,
            num_sources: 0,
            multicast_addr: ALL_NODES,
            source_addrs: Vec::new(),
            auxiliary_data: Vec::new(),
        };
        assert_eq!(odd_record.validate(), Ok(()));

        // A record pointed at a unicast group fails, and the failure
        // surfaces through the enclosing Report.
        let bad_report = MldV2MulticastListenerReport {
            num_records: 1,
            records: Repeated::new(vec![MldV2AddressRecord {
                record_type: MldV2RecordType::MODE_IS_INCLUDE,
                aux_data_len: 0,
                num_sources: 0,
                multicast_addr: source(0x0a),
                source_addrs: Vec::new(),
                auxiliary_data: Vec::new(),
            }]),
            ..Default::default()
        };
        assert_eq!(
            bad_report.validate(),
            Err(MldValidationError::GroupNotMulticast)
        );
    }
}
