use ingot_types::Header;
use ingot_types::HeaderParse;
use ingot_types::OneChunk;

use super::*;
// use ingot_types::PacketParse;

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
    let mut buf2 = [0u8; Ethernet::MINIMUM_LENGTH + Ipv6::MINIMUM_LENGTH];

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
}
