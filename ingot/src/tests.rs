use core::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    ethernet::{Ethernet, EthernetMut, EthernetRef, ValidEthernet},
    geneve::{GeneveRef, ValidGeneve},
    ip::{
        Ecn, Ipv4, Ipv4Mut, Ipv4Ref, Ipv6, Ipv6Mut, Ipv6Ref, ValidIpv4,
        ValidIpv6,
    },
    udp::{Udp, UdpMut, UdpRef, ValidUdp},
};
use alloc::{collections::LinkedList, vec::Vec};
use ethernet::Ethertype;
use example_chain::{OpteIn, OpteOut, UltimateChain, L3};
use geneve::{Geneve, GeneveFlags};
use ingot_types::{
    primitives::*, Emit, Header, HeaderParse, NetworkRepr, ParseChoice,
    ParseError, Parsed, RepeatedView,
};
use ip::{
    IpProtocol, IpV6Ext6564, IpV6Ext6564Ref, IpV6ExtFragmentRef,
    LowRentV6EhRepr, ValidLowRentV6Eh,
};
use macaddr::MacAddr6;

use super::*;

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
fn are_my_fragment_traits_sane() {
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH + Ipv6::MINIMUM_LENGTH];
    let (mut eth, .., rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();

    // 0 is a valid v6 EH -- need to change to e.g. TCP before parse.
    rest[6] = IpProtocol::TCP.to_network();
    let (.., rest) = ValidIpv6::parse(&mut rest[..]).unwrap();
    assert_eq!(rest.len(), 0);
    assert_eq!(eth.source(), MacAddr6::nil());
    eth.set_source(MacAddr6::broadcast());
    assert_eq!(eth.source(), MacAddr6::broadcast());

    // v6.set_source(Ipv6Addr::LOCALHOST);
    // assert_eq!(v6.source(), Ipv6Addr::LOCALHOST);

    Ecn::try_from(1u8).unwrap();
}

#[test]
fn does_this_chain_stuff_compile() {
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH
        + Ipv4::MINIMUM_LENGTH
        + Udp::MINIMUM_LENGTH];

    // set up stack as Ipv4, UDP
    {
        let (mut eth, .., rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();
        let (mut ipv4, .., rest) = ValidIpv4::parse(rest).unwrap();
        let _ = ValidUdp::parse(rest).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(Ethertype::IPV4);
        ipv4.set_protocol(IpProtocol::UDP);
        ipv4.set_source(Ipv4Addr::from([192, 168, 0, 1]));
        ipv4.set_destination(Ipv4Addr::from([192, 168, 0, 255]));
    }

    let _ = UltimateChain::parse(&mut buf2[..]).unwrap();
    let (mystack, ..) = UltimateChain::parse(&buf2[..]).unwrap();

    match mystack.l3 {
        L3::Ipv4(v) => v.hop_limit(),
        L3::Ipv6(v) => v.hop_limit(),
    };

    assert_eq!(
        mystack.eth.source(),
        MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
    );
}

#[test]
fn variable_len_fields_in_chain() {
    const V4_EXTRA: usize = 12;
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH
        + Ipv4::MINIMUM_LENGTH
        + V4_EXTRA
        + Udp::MINIMUM_LENGTH];

    // set up stack as Ipv4, UDP
    {
        let (mut eth, .., rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();
        let (mut ipv4, .., rest) = ValidIpv4::parse(rest).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(Ethertype::IPV4);
        ipv4.set_protocol(IpProtocol::UDP);
        ipv4.set_source(Ipv4Addr::from([192, 168, 0, 1]));
        ipv4.set_destination(Ipv4Addr::from([192, 168, 0, 255]));
        ipv4.set_ihl(5 + (V4_EXTRA as u8 / 4));

        for (i, b) in (&mut rest[..V4_EXTRA]).iter_mut().enumerate() {
            *b = i as u8;
        }
    }

    {
        let l = buf2.len();
        let (mut udp, .., rest) =
            ValidUdp::parse(&mut buf2[l - Udp::MINIMUM_LENGTH..]).unwrap();
        assert_eq!(rest.len(), 0);
        udp.set_source(6082);
        udp.set_destination(6081);
        udp.set_length(0);
        udp.set_checksum(0xffff);
    }

    let (mystack, ..) = UltimateChain::parse(&buf2[..]).unwrap();

    assert_eq!(
        mystack.eth.source(),
        MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
    );
    assert_eq!(mystack.eth.destination(), MacAddr6::broadcast());
    assert_eq!(mystack.eth.ethertype(), Ethertype::IPV4);

    let L3::Ipv4(v4) = mystack.l3 else {
        panic!("did not parse IPv4...");
    };
    assert_eq!(v4.protocol(), IpProtocol::UDP);
    assert_eq!(v4.source(), Ipv4Addr::from([192, 168, 0, 1]));
    assert_eq!(v4.destination(), Ipv4Addr::from([192, 168, 0, 255]));
    assert_eq!(v4.ihl(), 8);
    assert_eq!(
        v4.options_ref().as_ref(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );

    assert_eq!(mystack.l4.source(), 6082);
    assert_eq!(mystack.l4.destination(), 6081);
    assert_eq!(mystack.l4.length(), 0);
    assert_eq!(mystack.l4.checksum(), 0xffff);
}

#[test]
fn parse_multichunk() {
    let mut eth_bytes = vec![0u8; Ethernet::MINIMUM_LENGTH];
    let mut v6_bytes = vec![0u8; Ipv6::MINIMUM_LENGTH];
    // 0 is a valid v6 EH -- need to init it before parse.
    v6_bytes[6] = IpProtocol::UDP.to_network();
    let mut udp_bytes = vec![0u8; Udp::MINIMUM_LENGTH];
    let body_bytes = vec![0xaau8; 128];
    {
        let (mut eth, ..) = ValidEthernet::parse(&mut eth_bytes[..]).unwrap();
        let (mut ipv6, ..) = ValidIpv6::parse(&mut v6_bytes[..]).unwrap();
        let (mut udp, ..) = ValidUdp::parse(&mut udp_bytes[..]).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(Ethertype::IPV6);

        assert_eq!(ipv6.next_header(), IpProtocol::UDP);
        ipv6.set_source(Ipv6Addr::LOCALHOST);
        ipv6.set_destination(Ipv6Addr::UNSPECIFIED);

        udp.set_source(6082);
        udp.set_destination(6081);
        udp.set_length(body_bytes.len().try_into().unwrap());
        udp.set_checksum(0xffff);
    }

    let mut my_multi: LinkedList<Vec<u8>> = LinkedList::new();

    my_multi.push_back(eth_bytes);
    my_multi.push_back(v6_bytes);
    my_multi.push_back(udp_bytes);
    my_multi.push_back(body_bytes);

    let mut mystack = UltimateChain::parse_read(my_multi.iter_mut()).unwrap();

    let hdr = mystack.headers_mut();

    assert_eq!(hdr.eth.source(), MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
    assert_eq!(hdr.eth.destination(), MacAddr6::broadcast());
    assert_eq!(hdr.eth.ethertype(), Ethertype::IPV6);

    let L3::Ipv6(ref mut v6) = hdr.l3 else {
        panic!("did not parse IPv4...");
    };
    v6.set_version(6);
    assert_eq!(v6.version(), 6);
    assert_eq!(v6.next_header(), IpProtocol::UDP);
    assert_eq!(v6.source(), Ipv6Addr::LOCALHOST);
    assert_eq!(v6.destination(), Ipv6Addr::UNSPECIFIED);
    // assert_eq!(v6.ihl(), 8);
    // assert_eq!(v6.options_ref().as_ref(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

    assert_eq!(hdr.l4.source(), 6082);
    assert_eq!(hdr.l4.destination(), 6081);
    assert_eq!(hdr.l4.length(), 128);
    assert_eq!(hdr.l4.checksum(), 0xffff);

    let b = mystack.body().unwrap();

    assert_eq!(b.len(), 128);
    assert!(b.iter().all(|v| *v == 0xaa));

    let b = mystack.body_mut().unwrap();
    b.iter_mut().step_by(2).for_each(|v| *v = 0xbb);
}

#[test]
fn field_accesses_of_all_kinds() {
    // type has len: 24B
    #[rustfmt::skip]
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
fn test_opte_unconditionals() {
    #[rustfmt::skip]
    let mut pkt = [
        // ---OUTER ETH---
        // dst
        0xA8, 0x40, 0x25, 0x77, 0x77, 0x76,
        // src
        0xA8, 0x40, 0x25, 0x77, 0x77, 0x77,
        // ethertype
        0x86, 0xdd,

        // ---OUTER v6---
        // v6
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x11, 0xf0,
        // v6src
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // v6dst
        0xFD, 0x00, 0x00, 0x00, 0x00, 0xF7, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

        // ---OUTER UDP---
        // source
        0x1E, 0x61,
        // dest
        0x17, 0xC1,
        // length
        0x00, 0x14,
        // csum
        0x00, 0x00,

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

        // ---INNER ETH---
        // dst (guest)
        0xAA, 0x00, 0x04, 0x00, 0xFF, 0x10,
        // src (gateway)
        0xAA, 0x00, 0x04, 0x00, 0xFF, 0x01,
        // ethertype (v4)
        0x08, 0x00,

        // ---INNER v4---
        0x45, 0x00, 0x00, 28 + 8,
        0x00, 0x00, 0x00, 0x00,
        0xf0, 0x11, 0x00, 0x00,
        8, 8, 8, 8,
        192, 168, 0, 5,

        // ---INNER UDP---
        0x00, 0x80, 0x00, 53,
        0x00, 0x08, 0x00, 0x00,

        // ---INNER BODY---
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
    ];

    let (mut opte_in, ..) = OpteIn::parse(&mut pkt[..]).unwrap();

    assert_eq!(opte_in.outer_encap.options_ref().as_ref().len(), 4);
    assert_eq!(opte_in.inner_eth.ethertype(), Ethertype::IPV4);
    assert!(opte_in.inner_l3.is_some());
    assert!(opte_in.inner_ulp.is_some());

    // Now, try out pretending we're ARP and early exiting.
    opte_in.inner_eth.set_ethertype(Ethertype::ARP);
    let (opte_in, ..) = OpteIn::parse(&pkt[..]).unwrap();
    assert!(opte_in.inner_l3.is_none());
    assert!(opte_in.inner_ulp.is_none());
}

#[test]
fn chunks_present_on_early_accept() {
    #[rustfmt::skip]
    let pkt = [
        // ---OUTER ETH---
        // dst
        0xA8, 0x40, 0x25, 0x77, 0x77, 0x76,
        // src
        0xA8, 0x40, 0x25, 0x77, 0x77, 0x77,
        // ethertype
        0x08, 0x06,

        // Some bytes we wish to preserve...
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];

    let mut pkt_as_readable = LinkedList::new();
    pkt_as_readable.push_back(pkt[..14].to_vec());
    pkt_as_readable.push_back(pkt[14..].to_vec());

    let (opte_out, a, b) = OpteOut::parse(&pkt[..]).unwrap();
    assert_eq!(b.len(), 8);

    let Parsed { stack, data, last_chunk } =
        OpteOut::parse_read(pkt_as_readable.iter()).unwrap();
    // panic!("{data:?}, {last_chunk:?}");
    assert_eq!(last_chunk.packet_length(), 8);
    assert_eq!(data.len(), 0);
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
        0x00,
        // rsvd + len
        0x00,
    ];

    let (g, ..) = ValidGeneve::parse(&g_no_opt[..]).unwrap();
    assert_eq!(g.packet_length(), 8);

    let (g, ..) = ValidGeneve::parse(&g_opt[..]).unwrap();
    assert_eq!(g.packet_length(), 12);
}

#[test]
fn ipv6_bitset() {
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
                    &v6.0.bytes()[..4]
                );
                v6.set_ecn(Ecn::Capable1);
                eprintln!(
                    "(golden {golden:x?}, saw {:x?})",
                    &v6.0.bytes()[..4]
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
fn v6_extension_headers() {
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
        ingot_types::Packet::Repr(_) => panic!(),
        ingot_types::Packet::Raw(v) => {
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
}

#[test]
fn loopy() {
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

    let owned_g = Geneve::from(&g);
    assert_eq!(owned_g.version, 0);
    assert_eq!(owned_g.opt_len, 1);
    assert_eq!(owned_g.flags, GeneveFlags::empty());
    assert_eq!(owned_g.protocol_type, Ethertype::ETHERNET);
    assert_eq!(owned_g.vni, 0x0004d2);
    assert_eq!(owned_g.reserved, 0);

    assert_eq!(owned_g.options, &[0x01, 0x29, 0x00, 0x00]);

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

    // let a = &owned_v6.v6ext[0];
    assert!(matches!(&owned_v6.v6ext[0], LowRentV6EhRepr::IpV6Ext6564(_)));
    assert!(matches!(&owned_v6.v6ext[1], LowRentV6EhRepr::IpV6ExtFragment(_)));
    assert!(matches!(&owned_v6.v6ext[2], LowRentV6EhRepr::IpV6Ext6564(_)));
}

#[test]
fn roundtrip() {
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
fn ez_emit() {
    let makeshift_stack = (
        Udp { source: 1234, destination: 5678, length: 77, checksum: 0xffff },
        Geneve {
            flags: GeneveFlags::CRITICAL_OPTS,
            protocol_type: Ethertype::ETHERNET,
            vni: 7777,
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
    assert_eq!(geneve.vni(), 7777);
    assert_eq!(geneve.reserved(), 0);
}
