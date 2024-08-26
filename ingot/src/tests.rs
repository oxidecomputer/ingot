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
use example_chain::{OpteIn, UltimateChain, L3};
use ingot_types::{primitives::*, BufState, Header, HeaderParse};
use ip::IpProtocol;
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
    let mut buf2 =
        [0u8; Ethernet::MINIMUM_LENGTH + Ipv6::<&[u8]>::MINIMUM_LENGTH];
    // let mut eth = EthernetView::
    let BufState { val: mut eth, remainder: rest, .. } =
        ValidEthernet::parse(&mut buf2[..]).unwrap();
    let BufState { val: v6, remainder: rest, .. } =
        ValidIpv6::parse(&mut rest[..]).unwrap();
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
        + Ipv4::<&[u8]>::MINIMUM_LENGTH
        + Udp::MINIMUM_LENGTH];

    // set up stack as Ipv4, UDP
    {
        let BufState { val: mut eth, remainder: rest, .. } =
            ValidEthernet::parse(&mut buf2[..]).unwrap();
        let BufState { val: mut ipv4, remainder: rest, .. } =
            ValidIpv4::parse(rest).unwrap();
        let BufState { .. } = ValidUdp::parse(rest).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(0x0800);
        ipv4.set_protocol(IpProtocol::UDP);
        ipv4.set_source(Ipv4Addr::from([192, 168, 0, 1]));
        ipv4.set_destination(Ipv4Addr::from([192, 168, 0, 255]));
    }

    let BufState { .. } = UltimateChain::parse(&mut buf2[..]).unwrap();
    let BufState { val: mystack, .. } =
        UltimateChain::parse(&buf2[..]).unwrap();

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
        + Ipv4::<&[u8]>::MINIMUM_LENGTH
        + V4_EXTRA
        + Udp::MINIMUM_LENGTH];

    // set up stack as Ipv4, UDP
    {
        let BufState { val: mut eth, remainder: rest, .. } =
            ValidEthernet::parse(&mut buf2[..]).unwrap();
        let BufState { val: mut ipv4, remainder: rest, .. } =
            ValidIpv4::parse(rest).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(0x0800);
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
        let BufState { val: mut udp, remainder: rest, .. } =
            ValidUdp::parse(&mut buf2[l - Udp::MINIMUM_LENGTH..]).unwrap();
        assert_eq!(rest.len(), 0);
        udp.set_source(6082);
        udp.set_destination(6081);
        udp.set_length(0);
        udp.set_checksum(0xffff);
    }

    let BufState { val: mystack, .. } =
        UltimateChain::parse(&buf2[..]).unwrap();

    assert_eq!(
        mystack.eth.source(),
        MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
    );
    assert_eq!(mystack.eth.destination(), MacAddr6::broadcast());
    assert_eq!(mystack.eth.ethertype(), 0x0800);

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
    let mut v6_bytes = vec![0u8; Ipv6::<&[u8]>::MINIMUM_LENGTH];
    let mut udp_bytes = vec![0u8; Udp::MINIMUM_LENGTH];
    let body_bytes = vec![0xaau8; 128];
    {
        let BufState { val: mut eth, .. } =
            ValidEthernet::parse(&mut eth_bytes[..]).unwrap();
        let BufState { val: mut ipv6, .. } =
            ValidIpv6::parse(&mut v6_bytes[..]).unwrap();
        let BufState { val: mut udp, .. } =
            ValidUdp::parse(&mut udp_bytes[..]).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(0x86DD);

        ipv6.set_next_header(IpProtocol::UDP);
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
    assert_eq!(hdr.eth.ethertype(), 0x86DD);

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

    let BufState { val: mut a, .. } =
        ValidTestFunFields::parse(&mut base_bytes[..]).unwrap();

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

    let BufState { val: mut opte_in, .. } =
        OpteIn::parse(&mut pkt[..]).unwrap();

    assert_eq!(opte_in.outer_encap.options_ref().as_ref().len(), 4);
    assert_eq!(opte_in.inner_eth.ethertype(), 0x0800);
    assert!(opte_in.inner_l3.is_some());
    assert!(opte_in.inner_ulp.is_some());

    // Now, try out pretending we're ARP and early exiting.
    opte_in.inner_eth.set_ethertype(0x0806);
    let BufState { val: opte_in, .. } = OpteIn::parse(&pkt[..]).unwrap();
    assert!(opte_in.inner_l3.is_none());
    assert!(opte_in.inner_ulp.is_none());
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

    let BufState { val: g, .. } = ValidGeneve::parse(&g_no_opt[..]).unwrap();
    assert_eq!(g.packet_length(), 8);

    let BufState { val: g, .. } = ValidGeneve::parse(&g_opt[..]).unwrap();
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

    let BufState { val: mut v6, .. } = ValidIpv6::parse(&mut pkt[..]).unwrap();

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
