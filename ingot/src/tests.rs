use alloc::collections::LinkedList;
use ingot_types::Header;
use ingot_types::HeaderParse;
use ingot_types::OneChunk;

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
    // let mut eth = EthernetView::
    let (mut eth, rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();
    let (mut v6, rest) = ValidIpv6::parse(&mut rest[..]).unwrap();
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
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH + Ipv4::<&[u8]>::MINIMUM_LENGTH + Udp::MINIMUM_LENGTH];

    // set up stack as Ipv4, UDP
    {
        let (mut eth, rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();
        let (mut ipv4, rest) = ValidIpv4::parse(rest).unwrap();
        let (mut udp, rest) = ValidUdp::parse(rest).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(0x0800);
        ipv4.set_protocol(0x11);
        ipv4.set_source(Ipv4Addr::from([192, 168, 0, 1]));
        ipv4.set_destination(Ipv4Addr::from([192, 168, 0, 255]));
    }

    let mystack = Parsed2::newy(OneChunk::from(&mut buf2[..])).unwrap();
    let mystack = Parsed2::newy(OneChunk::from(&buf2[..])).unwrap();

    match mystack.stack.0.l3 {
        L3::Ipv4(v) => v.hop_limit(),
        L3::Ipv6(v) => v.hop_limit(),
    };

    assert_eq!(
        mystack.stack.0.eth.source(),
        MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
    );
}

#[test]
fn variable_len_fields_in_chain() {
    const V4_EXTRA: usize = 12;
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH + Ipv4::<&[u8]>::MINIMUM_LENGTH + V4_EXTRA + Udp::MINIMUM_LENGTH];

    // set up stack as Ipv4, UDP
    {
        let (mut eth, rest) = ValidEthernet::parse(&mut buf2[..]).unwrap();
        let (mut ipv4, rest) = ValidIpv4::parse(rest).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(0x0800);
        ipv4.set_protocol(0x11);
        ipv4.set_source(Ipv4Addr::from([192, 168, 0, 1]));
        ipv4.set_destination(Ipv4Addr::from([192, 168, 0, 255]));
        ipv4.set_ihl(5 + (V4_EXTRA as u8 / 4));

        for (i, b) in (&mut rest[..V4_EXTRA]).iter_mut().enumerate() {
            *b = i as u8;
        }
    }

    {
        let l = buf2.len();
        let (mut udp, rest) = ValidUdp::parse(&mut buf2[l - Udp::MINIMUM_LENGTH..]).unwrap();
        assert_eq!(rest.len(), 0);
        udp.set_source(6082);
        udp.set_destination(6081);
        udp.set_length(0);
        udp.set_checksum(0xffff);
    }

    let mystack = Parsed2::newy(OneChunk::from(&buf2[..])).unwrap();

    assert_eq!(
        mystack.stack.0.eth.source(),
        MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
    );
    assert_eq!(
        mystack.stack.0.eth.destination(),
        MacAddr6::broadcast()
    );
    assert_eq!(
        mystack.stack.0.eth.ethertype(),
        0x0800
    );

    let L3::Ipv4(v4) = mystack.stack.0.l3 else {
        panic!("did not parse IPv4...");
    };
    assert_eq!(v4.protocol(), 0x11);
    assert_eq!(v4.source(), Ipv4Addr::from([192, 168, 0, 1]));
    assert_eq!(v4.destination(), Ipv4Addr::from([192, 168, 0, 255]));
    assert_eq!(v4.ihl(), 8);
    assert_eq!(v4.options_ref().as_ref(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

    assert_eq!(mystack.stack.0.l4.source(), 6082);
    assert_eq!(mystack.stack.0.l4.destination(), 6081);
    assert_eq!(mystack.stack.0.l4.length(), 0);
    assert_eq!(mystack.stack.0.l4.checksum(), 0xffff);
}

#[test]
fn parse_multichunk() {
    let mut eth_bytes = vec![0u8; Ethernet::MINIMUM_LENGTH];
    let mut v6_bytes = vec![0u8; Ipv6::MINIMUM_LENGTH];
    let mut udp_bytes = vec![0u8; Udp::MINIMUM_LENGTH];
    let mut body_bytes = vec![0u8; 128];
    {
        let (mut eth, _) = ValidEthernet::parse(&mut eth_bytes[..]).unwrap();
        let (mut ipv6, _) = ValidIpv6::parse(&mut v6_bytes[..]).unwrap();
        let (mut udp, _) = ValidUdp::parse(&mut udp_bytes[..]).unwrap();

        eth.set_source(MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf));
        eth.set_destination(MacAddr6::broadcast());
        eth.set_ethertype(0x86DD);

        ipv6.set_next_header(0x11);
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

    let mystack = Parsed2::newy(my_multi.iter_mut()).unwrap();

    assert_eq!(
        mystack.stack.0.eth.source(),
        MacAddr6::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
    );
    assert_eq!(
        mystack.stack.0.eth.destination(),
        MacAddr6::broadcast()
    );
    assert_eq!(
        mystack.stack.0.eth.ethertype(),
        0x86DD
    );

    let L3::Ipv6(mut v6) = mystack.stack.0.l3 else {
        panic!("did not parse IPv4...");
    };
    v6.set_version(6);
    assert_eq!(v6.version(), 6);
    assert_eq!(v6.next_header(), 0x11);
    assert_eq!(v6.source(), Ipv6Addr::LOCALHOST);
    assert_eq!(v6.destination(), Ipv6Addr::UNSPECIFIED);
    // assert_eq!(v6.ihl(), 8);
    // assert_eq!(v6.options_ref().as_ref(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

    assert_eq!(mystack.stack.0.l4.source(), 6082);
    assert_eq!(mystack.stack.0.l4.destination(), 6081);
    assert_eq!(mystack.stack.0.l4.length(), 128);
    assert_eq!(mystack.stack.0.l4.checksum(), 0xffff);
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

    let (mut a, _rest) =
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
