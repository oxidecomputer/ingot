// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    ethernet::{Ethernet, EthernetMut, EthernetRef, Ethertype, ValidEthernet},
    geneve::{
        Geneve, GeneveFlags, GeneveOpt, GeneveOptionType, GeneveRef,
        ValidGeneve,
    },
    ip::{
        Ecn, IpProtocol, IpV6Ext6564, IpV6Ext6564Ref, IpV6ExtFragmentRef, Ipv6,
        Ipv6Mut, Ipv6Ref, LowRentV6EhRepr, ValidIpv6, ValidLowRentV6Eh,
    },
    types::{
        primitives::*, util::RepeatedView, Accessor, Emit, HeaderLen,
        HeaderParse, Ipv6Addr, NextLayer, NextLayerChoice, ParseChoice,
        ParseError, ToOwnedPacket,
    },
    udp::{Udp, UdpRef, ValidUdp, _Udp_ingot_impl::UdpPart0},
    Ingot,
};
use core::mem;
use macaddr::MacAddr6;
use zerocopy::IntoBytes;

#[derive(Ingot)]
pub struct TestFunFields {
    pub fine: u8,
    pub memcpy_be: u24be,
    pub memcpy_le: u24le,
    pub still_fine: u8,

    pub tricky_be0: u9be,
    pub tricky_be1: u9be,
    pub tricky_be2: u14be,

    pub trickier_be0: u1,
    pub trickier_be1: u30be,
    pub trickier_be2: u1,

    pub tricky_le0: u9le,
    pub tricky_le1: u9le,
    pub tricky_le2: u14le,

    pub trickier_le0: u1,
    pub trickier_le1: u30le,
    pub trickier_le2: u1,

    pub tricky_he0: u9he,
    pub tricky_he1: u9he,
    pub tricky_he2: u14he,

    pub also_fine: u32be,
}

#[test]
fn base_parse_and_type_conversion() {
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH + Ipv6::MINIMUM_LENGTH];
    let (mut eth, .., rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();

    // 0 is a valid v6 EH -- need to change to e.g. TCP before parse.
    rest[6] = IpProtocol::TCP.0;
    let (.., rest) = ValidIpv6::parse(&mut rest[..]).unwrap();
    assert_eq!(rest.len(), 0);
    assert_eq!(eth.source(), MacAddr6::nil());
    eth.set_source(MacAddr6::broadcast());
    assert_eq!(eth.source(), MacAddr6::broadcast());

    Ecn::try_from(1u8).unwrap();
}

#[test]
fn unaligned_bitfield_read_write() {
    // type has len: 24B
    #[rustfmt::skip]
    #[allow(clippy::unusual_byte_groupings)]
    let mut base_bytes = [
        // 1, 10_560_325
        0x01, 0xa1, 0x23, 0x45,
        // 10_560_325, 255
        0x45, 0x23, 0xa1, 0xff,
        // 257, 258, 16_026
        //be0-----------|be1-----------|be2-----------------|
        0b1000_0000, 0b1_100_0000, 0b10_11_1110, 0b1001_1010,
        //1, 0x2AAA_AAAA, 0
        //b|tb0-------------------------------------------|b|
        0b1_101_0101, 0b0101_0101, 0b0101_0101, 0b0101_010_0,
        // 257, 258, 16_026
        //le0-----------|le1-----------|le2-----------------|
        0b0000_0001, 0b1_000_0001, 0b01_10_0110, 0b1011_1110,
        //1, 0x2AAA_AAAA, 0
        //b|tb0-------------------------------------------|b|
        0b1_101_0101, 0b0101_0101, 0b0101_0101, 0b0101_010_0,
        //he0-----------|he1-----------|he2-----------------|
        0b0000_0000, 0b1_000_0000, 0b00_00_0000, 0b0000_0000,
        // 31_326_686
        0x01, 0xde, 0x01, 0xde,
    ];

    let (mut a, ..) = ValidTestFunFields::parse(&mut base_bytes[..]).unwrap();

    assert_eq!(a.fine(), 1, "fine");
    assert_eq!(a.memcpy_be(), 10_560_325, "memcpy_be");
    assert_eq!(a.memcpy_le(), 10_560_325, "memcpy_le");
    assert_eq!(a.still_fine(), 255, "still_fine");

    assert_eq!(a.tricky_be0(), 257, "tricky_be0");
    assert_eq!(a.tricky_be1(), 258, "tricky_be1");
    assert_eq!(a.tricky_be2(), 16_026, "tricky_be2");

    assert_eq!(a.trickier_be0(), 1, "trickier_be0");
    assert_eq!(a.trickier_be1(), 0x2AAA_AAAA, "trickier_be1");
    assert_eq!(a.trickier_be2(), 0, "trickier_be2");

    // TODO: impl trickier LEs.
    assert_eq!(a.tricky_le0(), 257, "tricky_le0");

    // SETTERS
    a.set_fine(0xff);
    assert_eq!(a.fine(), 0xff, "set_fine");
    a.set_memcpy_be(0x22_2324);
    assert_eq!(a.memcpy_be(), 0x22_2324, "set_memcpy_be");
    a.set_memcpy_le(0x22_2324);
    assert_eq!(a.memcpy_le(), 0x22_2324, "set_memcpy_le");
    a.set_still_fine(0x0f);
    assert_eq!(a.still_fine(), 0x0f, "set_still_fine");

    a.set_tricky_be0(300);
    assert_eq!(a.tricky_be0(), 300, "set_tricky_be0");
    a.set_tricky_be1(301);
    assert_eq!(a.tricky_be1(), 301, "set_tricky_be1");
    a.set_tricky_be2(13_011);
    assert_eq!(a.tricky_be2(), 13_011, "set_tricky_be2");

    a.set_trickier_be0(0);
    assert_eq!(a.trickier_be0(), 0, "set_trickier_be0");
    a.set_trickier_be1(0x1BBB_BBBB);
    assert_eq!(a.trickier_be1(), 0x1BBB_BBBB, "set_trickier_be1");
    a.set_trickier_be2(1);
    assert_eq!(a.trickier_be2(), 1, "set_trickier_be2");

    a.set_tricky_le0(36);
    assert_eq!(a.tricky_le0(), 36, "set_tricky_le0");

    // assert_eq!(a.tricky_le2(), 16_026, "tricky_le2");
    // a.set_tricky_le2(16_027);
    // assert_eq!(a.tricky_le2(), 16_027, "tricky_le2");

    // nothing got unduly unset.
    assert_eq!(a.fine(), 0xff, "check_fine");
    assert_eq!(a.memcpy_be(), 0x22_2324, "check_memcpy_be");
    assert_eq!(a.memcpy_le(), 0x22_2324, "check_memcpy_le");
    assert_eq!(a.still_fine(), 0x0f, "check_still_fine");

    assert_eq!(a.tricky_be0(), 300, "check_tricky_be0");
    assert_eq!(a.tricky_be1(), 301, "check_tricky_be1");
    assert_eq!(a.tricky_be2(), 13_011, "check_tricky_be2");

    assert_eq!(a.trickier_be0(), 0, "check_trickier_be0");
    assert_eq!(a.trickier_be1(), 0x1BBB_BBBB, "check_trickier_be1");
    assert_eq!(a.trickier_be2(), 1, "check_trickier_be2");

    assert_eq!(a.tricky_le0(), 36, "check_tricky_le0");
}

#[test]
fn varlen_geneve() {
    #[rustfmt::skip]
    let g_no_opt = [
        // ---GENEVE WITH OPT---
        // ver + opt len
        0x00,
        // flags
        0x00,
        // proto
        0x65, 0x58,
        // vni + reserved
        0x00, 0x04, 0xD2, 0x00,
    ];

    #[rustfmt::skip]
    let g_opt = [
        // ---GENEVE WITH OPT---
        // ver + opt len
        0x01,
        // flags
        0x00,
        // proto
        0x65, 0x58,
        // vni + reserved
        0x00, 0x04, 0xD2, 0x00,

        // option class
        0x01, 0x29,
        // crt + type
        0x47,
        // rsvd + len
        0x00,
    ];

    let (g, ..) = ValidGeneve::parse(&g_no_opt[..]).unwrap();
    assert_eq!(g.packet_length(), 8);

    let (g, ..) = ValidGeneve::parse(&g_opt[..]).unwrap();
    assert_eq!(g.packet_length(), 12);

    let a = g.1.raw().unwrap();
    let parsed_opt = a.to_owned(None).unwrap();
    assert_eq!(parsed_opt.len(), 1);
    assert_eq!(
        parsed_opt[0],
        GeneveOpt {
            class: 0x0129,
            option_type: GeneveOptionType(0x47),
            reserved: 0,
            length: 0,
            data: vec![]
        }
    );
}

#[test]
fn bitset_fields_do_not_disturb_neighbours() {
    let golden = [0x6A, 0x61, 0xe2, 0x40];
    #[rustfmt::skip]
    let mut pkt = [
        // ---OUTER v6---
        // v6
        0x6A, 0x61, 0xe2, 0x40,
        0x00, 0x10, 0x11, 0xf0,
        // v6src
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // v6dst
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let (mut v6, ..) = ValidIpv6::parse(&mut pkt[..]).unwrap();

    for i in 0..5 {
        match i {
            1 => {
                v6.set_version(6);
            }
            2 => {
                v6.set_dscp(41);
            }
            3 => {
                eprintln!(
                    "(golden {golden:x?}, saw {:x?})",
                    &v6.0.as_bytes()[..4]
                );
                v6.set_ecn(Ecn::Capable1);
                eprintln!(
                    "(golden {golden:x?}, saw {:x?})",
                    &v6.0.as_bytes()[..4]
                );
            }
            4 => v6.set_flow_label(123456),
            _ => {}
        }

        assert_eq!(
            v6.version(),
            6,
            "version mismatch in iter {} (golden {golden:x?}, saw {:x?})",
            i,
            &pkt[..4]
        );
        assert_eq!(
            v6.dscp(),
            41,
            "dscp mismatch in iter {} (golden {golden:x?}, saw {:x?})",
            i,
            &pkt[..4]
        );
        assert_eq!(
            v6.ecn(),
            Ecn::Capable1,
            "ecn mismatch in iter {} (golden {golden:x?}, saw {:x?})",
            i,
            &pkt[..4]
        );
        assert_eq!(
            v6.flow_label(),
            123456,
            "flow mismatch in iter {} (golden {golden:x?}, saw {:x?})",
            i,
            &pkt[..4]
        );
    }
}

#[test]
fn v6_repeat_extension_headers() {
    #[rustfmt::skip]
    let bytes = [
        // ---OUTER v6---
        // v6 -> HBH
        0x6A, 0x61, 0xe2, 0x40,
        0x00, 0x10, 0x00, 0xf0,
        // v6src
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // v6dst
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

        // IPv6 Hop-by-hop -> Fragment
        // 6564 Header...
        44, 0x00,
        // body bytes.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // IPv6 Fragment -> Experiment(253)
        253, 0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        // IPv6 Experiment -> UDP
        // 6564 Header...
        0x11, 0x04,
        // body bytes.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let (v6, hint, _) = ValidIpv6::parse(&bytes[..]).unwrap();
    // v6.

    // assert_eq!(v6.().len(), 56);

    assert_eq!(hint, Some(IpProtocol::UDP));

    // TODO: ergonomics
    match v6.1 {
        ingot_types::Header::Repr(_) => panic!(),
        ingot_types::Header::Raw(ref v) => {
            let mut t = v.iter(Some(IpProtocol::IPV6_HOP_BY_HOP));
            let hbh = t.next().unwrap().unwrap();
            let ValidLowRentV6Eh::IpV6Ext6564(hbh) = hbh else { panic!() };
            assert_eq!(hbh.next_header(), IpProtocol::IPV6_FRAGMENT);
            assert_eq!(hbh.ext_len(), 0);

            let frag = t.next().unwrap().unwrap();
            let ValidLowRentV6Eh::IpV6ExtFragment(frag) = frag else {
                panic!()
            };
            assert_eq!(frag.next_header(), IpProtocol::IPV6_EXPERIMENT0);

            let experiment = t.next().unwrap().unwrap();
            let ValidLowRentV6Eh::IpV6Ext6564(experiment) = experiment else {
                panic!()
            };
            assert_eq!(experiment.next_header(), IpProtocol::UDP);
            assert_eq!(experiment.ext_len(), 4);
        }
    }

    assert_eq!(
        v6.1.next_layer_choice(Some(IpProtocol::IPV6_HOP_BY_HOP)),
        Some(IpProtocol::UDP)
    );
    assert_eq!(v6.next_layer(), Some(IpProtocol::UDP));
}

#[test]
fn repeated_on_standard_header() {
    let bytes = [0u8; 24];
    let _ = ValidUdp::<&[u8]>::parse_choice(&bytes[..], Some(())).unwrap();
    let _ =
        RepeatedView::<&[u8], Udp>::parse_choice(&bytes[..], Some(())).unwrap();
    assert!(matches!(
        RepeatedView::<&[u8], Udp>::parse_choice(&bytes[..20], Some(())),
        Err(ParseError::TooSmall)
    ));
}

#[test]
fn to_owned() {
    #[rustfmt::skip]
    let g_opt = [
        // ---GENEVE WITH OPT---
        // ver + opt len
        0x01,
        // flags
        0x00,
        // proto
        0x65, 0x58,
        // vni + reserved
        0x00, 0x04, 0xD2, 0x00,

        // option class
        0x01, 0x29,
        // crt + type
        0x00,
        // rsvd + len
        0x00,
    ];

    let (g, ..) = ValidGeneve::parse(&g_opt[..]).unwrap();

    let owned_g = Geneve::try_from(&g).unwrap();
    assert_eq!(owned_g.version, 0);
    assert_eq!(owned_g.opt_len, 1);
    assert_eq!(owned_g.flags, GeneveFlags::empty());
    assert_eq!(owned_g.protocol_type, Ethertype::ETHERNET);
    assert_eq!(owned_g.vni, 0x0004d2.try_into().unwrap());
    assert_eq!(owned_g.reserved, 0);

    assert_eq!(
        &owned_g.options[..],
        &[GeneveOpt { class: 0x0129, ..Default::default() }]
    );

    #[rustfmt::skip]
    let bytes = [
        // ---OUTER v6---
        // v6 -> HBH
        0x6A, 0x61, 0xe2, 0x40,
        0x00, 0x10, 0x00, 0xf0,
        // v6src
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // v6dst
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

        // IPv6 Hop-by-hop -> Fragment
        // 6564 Header...
        44, 0x00,
        // body bytes.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // IPv6 Fragment -> Experiment(253)
        253, 0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        // IPv6 Experiment -> UDP
        // 6564 Header...
        0x11, 0x04,
        // body bytes.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let (v6, ..) = ValidIpv6::parse(&bytes[..]).unwrap();
    let owned_v6 = Ipv6::try_from(&v6).unwrap();

    assert!(matches!(&owned_v6.v6ext[0], LowRentV6EhRepr::IpV6Ext6564(_)));
    assert!(matches!(&owned_v6.v6ext[1], LowRentV6EhRepr::IpV6ExtFragment(_)));
    assert!(matches!(&owned_v6.v6ext[2], LowRentV6EhRepr::IpV6Ext6564(_)));
}

#[test]
fn roundtrip_emit_parse_unchanged() {
    let udp =
        Udp { source: 1234, destination: 5678, length: 77, checksum: 0xffff };

    let as_bytes = udp.to_vec();
    let (p_udp, ..) = ValidUdp::parse(&as_bytes[..]).unwrap();
    assert_eq!(udp, (&p_udp).into());

    let as_bytes = udp.emit_vec();
    let (p_udp, ..) = ValidUdp::parse(&as_bytes[..]).unwrap();
    assert_eq!(udp, (&p_udp).into());

    let v6 = Ipv6 {
        version: 6,
        dscp: 0,
        ecn: Ecn::Capable1,
        flow_label: 123456,
        payload_len: 77,
        next_header: IpProtocol::IPV6_HOP_BY_HOP,
        hop_limit: 128,
        source: Ipv6Addr::LOCALHOST,
        destination: Ipv6Addr::UNSPECIFIED,
        v6ext: vec![IpV6Ext6564 {
            next_header: IpProtocol::IPV6_NO_NH,
            ext_len: 0,
            data: vec![0u8; 6],
        }
        .into()]
        .into(),
    };

    let as_bytes = v6.to_vec();
    let (p_v6, ..) = ValidIpv6::parse(&as_bytes[..]).unwrap();
    assert_eq!(v6, (&p_v6).try_into().unwrap());

    let as_bytes = v6.emit_vec();
    let (p_v6, ..) = ValidIpv6::parse(&as_bytes[..]).unwrap();
    assert_eq!(v6, (&p_v6).try_into().unwrap());
}

#[test]
fn easy_tuple_emit() {
    let makeshift_stack = (
        Udp { source: 1234, destination: 5678, length: 77, checksum: 0xffff },
        Geneve {
            flags: GeneveFlags::CRITICAL_OPTS,
            protocol_type: Ethertype::ETHERNET,
            vni: 7777.try_into().unwrap(),
            ..Default::default()
        },
    );

    let out = makeshift_stack.emit_vec();

    let (udp, ..) = ValidUdp::parse(&out[..8]).unwrap();
    assert_eq!(udp.source(), 1234);
    assert_eq!(udp.destination(), 5678);
    assert_eq!(udp.length(), 77);
    assert_eq!(udp.checksum(), 0xffff);

    let (geneve, ..) = ValidGeneve::parse(&out[8..]).unwrap();
    assert_eq!(geneve.version(), 0);
    assert_eq!(geneve.opt_len(), 0);
    assert_eq!(geneve.flags(), GeneveFlags::CRITICAL_OPTS);
    assert_eq!(geneve.protocol_type(), Ethertype::ETHERNET);
    assert_eq!(geneve.vni(), 7777.try_into().unwrap());
    assert_eq!(geneve.reserved(), 0);

    let ref_stack = (&makeshift_stack.0, &makeshift_stack.1);

    // Ensure that forwarding of Header, Emit, and EmitUninit work
    // via &T.
    let out = ref_stack.emit_vec();
    ValidUdp::parse(&out[..8]).unwrap();
    ValidGeneve::parse(&out[8..]).unwrap();
}

#[test]
fn accessor_functions_safely() {
    let makeshift_stack = (
        Udp { source: 1234, destination: 5678, length: 77, checksum: 0xffff },
        Geneve {
            flags: GeneveFlags::CRITICAL_OPTS,
            protocol_type: Ethertype::ETHERNET,
            vni: 7777.try_into().unwrap(),
            ..Default::default()
        },
    );

    let mut out = makeshift_stack.emit_vec();
    let _ = ValidUdp::parse(&out[..8]).unwrap();

    let (a, _): (Accessor<_, UdpPart0>, _) =
        Accessor::read_from_prefix(&out[..8]).unwrap();
    assert_eq!(mem::size_of_val(&a), mem::size_of::<*mut u8>());
    assert_eq!(u16::from(a.source), 1234);

    let (mut a, _): (Accessor<_, UdpPart0>, _) =
        Accessor::read_from_prefix(&mut out[..8]).unwrap();
    assert_eq!(mem::size_of_val(&a), mem::size_of::<*mut u8>());
    a.destination = 8989.into();
    assert_eq!(u16::from(a.destination), 8989);
}

#[derive(Ingot)]
pub struct OuterPacket {
    pub bla: u8,

    #[ingot(subparse())]
    pub next_packet: InnerPacket,
}

#[derive(Clone, Ingot)]
pub struct InnerPacket {
    pub boo: u8,
    #[ingot(var_len = "boo")]
    pub varying: alloc::vec::Vec<u8>,
}

#[test]
fn nested_packet_size() {
    let p = OuterPacket {
        bla: 1,
        next_packet: InnerPacket { boo: 2, varying: vec![1, 2] },
    };
    assert_eq!(p.packet_length(), 4);

    let p = OuterPacket {
        bla: 1,
        next_packet: InnerPacket { boo: 0, varying: vec![] },
    };
    assert_eq!(p.packet_length(), 2);
}
