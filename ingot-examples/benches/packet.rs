// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{criterion_group, criterion_main, Criterion};
use ingot::{
    types::HeaderParse,
    udp::{UdpMut, UdpRef},
};
use ingot_examples::packets::*;
use std::{collections::LinkedList, hint::black_box};

pub fn criterion_benchmark(c: &mut Criterion) {
    #[rustfmt::skip]
    let pkt_body_v4: &mut [u8] = &mut [
        // eth src : 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // eth dst
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        // Ethertype
        0x08, 0x00,
        // IPv4 : 14
        0x45, 0x00, 0x00, 28 + 8,
        0x00, 0x00, 0x00, 0x00,
        0xf0, 0x11, 0x00, 0x00,
        192, 168, 0, 1,
        192, 168, 0, 255,
        // UDP : 34
        0x00, 0x80, 0x17, 0xc1,
        0x00, 0x08, 0x00, 0x00,
        // body : 42
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
    ];
    #[rustfmt::skip]
    let pkt_body_v6: &mut [u8] = &mut [
        // eth src
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // eth dst
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        // Ethertype
        0x86, 0xdd,
        // v6
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x11, 0xf0,
        // v6src
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // v6dst
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // UDP
        0x00, 0x80, 0x17, 0xc1,
        0x00, 0x08, 0x00, 0x00,
        // body
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    #[rustfmt::skip]
    let opte_in_pkt = [
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
    let opte_out_pkt = &opte_in_pkt[opte_in_pkt.len() - 50..];
    let mut actual_chain_v4 = LinkedList::new();
    actual_chain_v4.push_front(pkt_body_v4[42..].to_vec());
    actual_chain_v4.push_front(pkt_body_v4[34..42].to_vec());
    actual_chain_v4.push_front(pkt_body_v4[14..34].to_vec());
    actual_chain_v4.push_front(pkt_body_v4[0..14].to_vec());

    c.bench_function("parse-stack-v4", |b| {
        b.iter(|| UdpParser::parse(black_box(&pkt_body_v4[..])).unwrap())
    });
    c.bench_function("parse-and-decr-v4", |b| {
        b.iter(|| {
            let (mut hdrs, ..) =
                UdpParser::parse(black_box(&mut pkt_body_v4[..])).unwrap();
            black_box(hdrs.l4.set_destination(hdrs.l4.destination() - 1));
        })
    });
    c.bench_function("parse-stack-v6", |b| {
        b.iter(|| UdpParser::parse(black_box(&pkt_body_v6[..])).unwrap())
    });
    c.bench_function("parse-valid-stack-v6", |b| {
        b.iter(|| ValidUdpParser::parse(black_box(&pkt_body_v6[..])).unwrap())
    });
    c.bench_function("parse-read-v4", |b| {
        b.iter(|| {
            UdpParser::parse_read(black_box(actual_chain_v4.iter())).unwrap()
        })
    });
    c.bench_function("parse-stack-opte-in", |b| {
        b.iter(|| {
            GeneveOverV6Tunnel::parse(black_box(&opte_in_pkt[..])).unwrap()
        })
    });
    c.bench_function("parse-valid-opte-in", |b| {
        b.iter(|| {
            ValidGeneveOverV6Tunnel::parse(black_box(&opte_in_pkt[..])).unwrap()
        })
    });
    c.bench_function("parse-stack-opte-out", |b| {
        b.iter(|| GenericUlp::parse(black_box(&opte_out_pkt[..])).unwrap())
    });
    c.bench_function("parse-valid-opte-out", |b| {
        b.iter(|| ValidGenericUlp::parse(black_box(&opte_out_pkt[..])).unwrap())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
