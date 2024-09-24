use criterion::{criterion_group, criterion_main, Criterion};
use ingot::{
    example_chain::{
        OpteIn, OpteOut, UltimateChain, ValidOpteIn, ValidOpteOut,
        ValidUltimateChain,
    },
    udp::{UdpMut, UdpRef, ValidUdp},
};
use ingot_types::HeaderParse;
use std::{collections::LinkedList, hint::black_box};

fn parse_udp(buf: &[u8]) -> ValidUdp<&[u8]> {
    ValidUdp::parse(buf).unwrap().0
}

pub fn criterion_benchmark(c: &mut Criterion) {
    #[rustfmt::skip]
    let pkt_body_v4: &mut[u8] = &mut [
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

    println!("size IN  is {}", core::mem::size_of::<OpteIn<&[u8]>>());
    println!("size OUT is {}", core::mem::size_of::<OpteOut<&[u8]>>());

    c.bench_function("parse-udp", |b| {
        b.iter(|| black_box(parse_udp(black_box(&pkt_body_v4[34..42]))))
    });
    c.bench_function("parse-stack-v4", |b| {
        b.iter(|| UltimateChain::parse(black_box(&pkt_body_v4[..])).unwrap())
    });
    c.bench_function("parse-and-decr-v4", |b| {
        b.iter(|| {
            let (mut hdrs, ..) =
                UltimateChain::parse(black_box(&mut pkt_body_v4[..])).unwrap();
            black_box(hdrs.l4.set_destination(hdrs.l4.destination() - 1));
        })
    });
    c.bench_function("parse-stack-v6", |b| {
        b.iter(|| UltimateChain::parse(black_box(&pkt_body_v6[..])).unwrap())
    });
    c.bench_function("parse-valid-stack-v6", |b| {
        b.iter(|| {
            ValidUltimateChain::parse(black_box(&pkt_body_v6[..])).unwrap()
        })
    });
    c.bench_function("parse-read-v4", |b| {
        b.iter(|| {
            UltimateChain::parse_read(black_box(actual_chain_v4.iter()))
                .unwrap()
        })
    });
    c.bench_function("parse-stack-opte-in", |b| {
        b.iter(|| OpteIn::parse(black_box(&opte_in_pkt[..])).unwrap())
    });
    c.bench_function("parse-valid-opte-in", |b| {
        b.iter(|| ValidOpteIn::parse(black_box(&opte_in_pkt[..])).unwrap())
    });
    c.bench_function("parse-stack-opte-out", |b| {
        b.iter(|| OpteOut::parse(black_box(&opte_out_pkt[..])).unwrap())
    });
    c.bench_function("parse-valid-opte-out", |b| {
        b.iter(|| ValidOpteOut::parse(black_box(&opte_out_pkt[..])).unwrap())
    });
    // c.bench_function("parsy2-stack-opte-in", |b| {
    //     b.iter(|| OpteIn::parsy2(black_box(&opte_in_pkt[..])).unwrap())
    // });
    // c.bench_function("parsy-stack-opte-in", |b| {
    //     b.iter(|| {
    //         let mut slot = None;
    //         let _rem =
    //             OpteIn::parsy(black_box(&opte_in_pkt[..]), &mut slot).unwrap();
    //         black_box(slot)
    //     })
    // });

    // let mut opte_in_pkt2 = opte_in_pkt;
    // let (mut opte_in, _unparsed) =
    //     OpteIn::parse(&mut opte_in_pkt2[..]).unwrap();
    // opte_in.inner_eth.set_ethertype(0x0806);
    // c.bench_function("parse-stack-opte-in-arp", |b| {
    //     b.iter(|| OpteIn::parse(black_box(&opte_in_pkt2[..])).unwrap())
    // });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
