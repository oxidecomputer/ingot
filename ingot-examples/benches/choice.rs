// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{criterion_group, criterion_main, Criterion};
use ingot::{ethernet::Ethertype, types::HeaderParse};
use ingot_examples::choices::ValidL3;
use std::hint::black_box;

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
    c.bench_function("choice-l3-success", |b| {
        b.iter(|| {
            ValidL3::parse_choice(
                black_box(&pkt_body_v4[14..]),
                Some(Ethertype::IPV4),
            )
        })
    });
    c.bench_function("choice-l3-fail", |b| {
        b.iter(|| {
            ValidL3::parse_choice(
                black_box(&pkt_body_v4[14..]),
                Some(Ethertype::LLDP),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
