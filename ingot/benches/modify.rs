use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use ingot::UdpMut;
use ingot::UdpRef;
use ingot::UltimateChain;
use ingot::ValidUdp;
use ingot_types::HeaderParse;
use ingot_types::OneChunk;
use std::collections::LinkedList;
use std::hint::black_box;

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
    let mut actual_chain_v4 = LinkedList::new();
    actual_chain_v4.push_front(pkt_body_v4[42..].to_vec());
    actual_chain_v4.push_front(pkt_body_v4[34..42].to_vec());
    actual_chain_v4.push_front(pkt_body_v4[14..34].to_vec());
    actual_chain_v4.push_front(pkt_body_v4[0..14].to_vec());

    c.bench_function("parse-udp", |b| {
        b.iter(|| ValidUdp::parse(black_box(&pkt_body_v4[34..42])).unwrap())
    });
    c.bench_function("parse-stack-v4", |b| {
        b.iter(|| UltimateChain::parse(black_box(&pkt_body_v4[..])).unwrap())
    });
    c.bench_function("parse-and-decr-v4", |b| {
        b.iter(|| {
            let (mut hdrs, _body) =
                UltimateChain::parse(black_box(&mut pkt_body_v4[..])).unwrap();
            hdrs.l4.set_destination(hdrs.l4.destination() - 1);
        })
    });
    c.bench_function("parse-stack-v6", |b| {
        b.iter(|| UltimateChain::parse(black_box(&pkt_body_v6[..])).unwrap())
    });
    c.bench_function("parse-read-v4", |b| {
        b.iter(|| {
            UltimateChain::parse_read(black_box(actual_chain_v4.iter()))
                .unwrap()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
