use crate::{choices::*, packets::*};
use core::net::{Ipv4Addr, Ipv6Addr};
use ingot::{
    ethernet::{Ethernet, EthernetMut, EthernetRef, Ethertype, ValidEthernet},
    geneve::GeneveRef,
    ip::{
        IpProtocol, Ipv4, Ipv4Mut, Ipv4Ref, Ipv6, Ipv6Mut, Ipv6Ref, ValidIpv4,
        ValidIpv6,
    },
    types::{
        HeaderLen, HeaderParse, NetworkRepr, NextLayer, ParseError, Parsed,
    },
    udp::{Udp, UdpMut, UdpRef, ValidUdp},
};
use macaddr::MacAddr6;
use std::collections::LinkedList;

#[test]
fn parse_header_chain_with_narrowing() {
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

    let _ = UdpParser::parse(&mut buf2[..]).unwrap();
    let (mystack, ..) = UdpParser::parse(&buf2[..]).unwrap();

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
fn variable_len_fields_in_header_chain() {
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

        for (i, b) in (rest[..V4_EXTRA]).iter_mut().enumerate() {
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

    let (mystack, ..) = UdpParser::parse(&buf2[..]).unwrap();

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
fn parse_header_chain_multichunk() {
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

    let mut mystack = UdpParser::parse_read(my_multi.iter_mut()).unwrap();

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
    assert_eq!(v6.next_layer(), Some(IpProtocol::UDP));
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
fn test_tunnelled_unconditionals() {
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

    let (mut opte_in, ..) = GeneveOverV6Tunnel::parse(&mut pkt[..]).unwrap();

    assert_eq!(opte_in.outer_encap.options_ref().packet_length(), 4);
    assert_eq!(opte_in.inner_eth.ethertype(), Ethertype::IPV4);
    assert!(opte_in.inner_l3.is_some());
    assert!(opte_in.inner_ulp.is_some());

    // Now, try out pretending we're ARP and early exiting.
    opte_in.inner_eth.set_ethertype(Ethertype::ARP);
    let (opte_in, ..) = GeneveOverV6Tunnel::parse(&pkt[..]).unwrap();
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

    let (_, _, b) = GenericUlp::parse(&pkt[..]).unwrap();
    assert_eq!(b.len(), 8);

    let Parsed { data, last_chunk, .. } =
        GenericUlp::parse_read(pkt_as_readable.iter()).unwrap();

    assert_eq!(last_chunk.packet_length(), 8);
    assert_eq!(data.len(), 0);
}

#[test]
fn parse_reports_error_location() {
    #[rustfmt::skip]
    let would_be_valid = [
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
    ];

    let Err(e) = GenericUlp::parse_slice(&would_be_valid[..4]) else {
        panic!("failed to reject truncated packet");
    };
    assert_eq!(*e.error(), ParseError::TooSmall);
    assert_eq!(e.header().as_str(), "inner_eth");

    let Err(e) = GenericUlp::parse_slice(&would_be_valid[..14]) else {
        panic!("failed to reject truncated packet");
    };
    assert_eq!(*e.error(), ParseError::TooSmall);
    assert_eq!(e.header().as_str(), "inner_l3");

    let Err(e) =
        GenericUlp::parse_slice(&would_be_valid[..would_be_valid.len() - 1])
    else {
        panic!("failed to reject truncated packet");
    };
    assert_eq!(*e.error(), ParseError::TooSmall);
    assert_eq!(e.header().as_str(), "inner_ulp");

    #[rustfmt::skip]
    let would_be_unwanted = [
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
        0xf0, 0x59, 0x00, 0x00,
        //    ^^^^ OSPF
        8, 8, 8, 8,
        192, 168, 0, 5,

        // ---arbitrary rejected payload---
        0x00, 0x80, 0x00, 53,
        0x00, 0x08, 0x00, 0x00,
    ];

    let Err(e) = GenericUlp::parse_slice(&would_be_unwanted[..]) else {
        panic!("failed to reject truncated packet");
    };
    assert_eq!(*e.error(), ParseError::Unwanted);
    assert_eq!(e.header().as_str(), "inner_ulp");
}
