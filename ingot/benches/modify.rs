// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{criterion_group, criterion_main, Criterion};
use ingot::{
    geneve::ValidGeneve,
    ip::{Ipv4Flags, Ipv4Mut, Ipv4Ref, ValidIpv4},
    types::HeaderParse,
    udp::ValidUdp,
};
use std::hint::black_box;

fn parse_udp(buf: &[u8]) -> ValidUdp<&[u8]> {
    ValidUdp::parse(buf).unwrap().0
}

pub fn criterion_benchmark(c: &mut Criterion) {
    #[rustfmt::skip]
    let pkt_body_udp: &mut [u8] = &mut [
        0x00, 0x80, 0x17, 0xc1,
        0x00, 0x08, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let pkt_body_geneve_no_opt: &mut [u8] = &mut [
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
    let pkt_body_geneve_opts: &mut [u8] = &mut [
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

    #[rustfmt::skip]
    let pkt_body_ipv4_no_opt: &mut [u8] = &mut [
        // ---INNER v4---
        0x45, 0x00, 0x00, 28 + 8,
        0x00, 0x00, 0x00, 0x00,
        0xf0, 0x11, 0x00, 0x00,
        8, 8, 8, 8,
        192, 168, 0, 5,
    ];

    #[rustfmt::skip]
    let pkt_body_ipv4_opts: &mut [u8] = &mut [
        // ---INNER v4---
        0x49, 0x00, 0x00, 28 + 8,
        0x00, 0x00, 0x00, 0x00,
        0xf0, 0x11, 0x00, 0x00,
        8, 8, 8, 8,
        192, 168, 0, 5,

        // as many bytes as we specified above the IHL.
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];

    c.bench_function("parse-udp", |b| {
        b.iter(|| black_box(parse_udp(black_box(pkt_body_udp))))
    });

    // Geneve and IP have varlen parts, IPV4's does not contain a subparse.
    c.bench_function("parse-geneve-no-opt", |b| {
        b.iter(|| {
            ValidGeneve::parse(black_box(&pkt_body_geneve_no_opt[..])).unwrap()
        })
    });

    c.bench_function("parse-geneve-opts", |b| {
        b.iter(|| {
            ValidGeneve::parse(black_box(&pkt_body_geneve_opts[..])).unwrap()
        })
    });

    c.bench_function("parse-ipv4-no-opt", |b| {
        b.iter(|| {
            ValidIpv4::parse(black_box(&pkt_body_ipv4_no_opt[..])).unwrap()
        })
    });

    c.bench_function("parse-ipv4-opts", |b| {
        b.iter(|| ValidIpv4::parse(black_box(&pkt_body_ipv4_opts[..])).unwrap())
    });

    // Test speed needed to get/set/convert fields.
    let (mut v4, ..) = ValidIpv4::parse(pkt_body_ipv4_no_opt).unwrap();

    c.bench_function("get-int", |b| {
        b.iter(|| {
            black_box(v4.total_len());
        })
    });

    c.bench_function("set-int", |b| {
        b.iter(|| {
            v4.set_total_len(black_box(128));
        })
    });

    c.bench_function("get-int-unaligned", |b| {
        b.iter(|| {
            black_box(v4.version());
        })
    });

    c.bench_function("set-int-unaligned", |b| {
        b.iter(|| {
            v4.set_version(black_box(4));
        })
    });

    c.bench_function("get-networkrepr-flags", |b| {
        b.iter(|| {
            black_box(v4.flags());
        })
    });

    c.bench_function("set-networkrepr-flags", |b| {
        b.iter(|| {
            v4.set_flags(black_box(Ipv4Flags::DONT_FRAGMENT));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
