use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use ingot::Parsed;
use ingot::UdpMut;
use ingot::UdpRef;
use ingot::ValidUdp;
use ingot_types::HeaderParse;
use ingot_types::OneChunk;
use std::hint::black_box;

pub fn criterion_benchmark(c: &mut Criterion) {
    #[rustfmt::skip]
    let pkt_body_v4: &mut[u8] = &mut [
        // eth src
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // eth dst
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        // Ethertype
        0x08, 0x00,
        // IPv4
        0x45, 0x00, 0x00, 28 + 8,
        0x00, 0x00, 0x00, 0x00,
        0xf0, 0x11, 0x00, 0x00,
        192, 168, 0, 1,
        192, 168, 0, 255,
        // UDP
        0x00, 0x80, 0x17, 0xc1,
        0x00, 0x08, 0x00, 0x00,
        // body
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
    ];
    let pkt_body_v6: &mut [u8] = &mut [
        // eth src
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // eth dst
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Ethertype
        0x86, 0xdd, // v6
        0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0xf0, // v6src
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // v6dst
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // UDP
        0x00, 0x80, 0x17, 0xc1, 0x00, 0x08, 0x00, 0x00, // body
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    c.bench_function("parse-stack-v6-lmao", |b| {
        b.iter(|| Parsed::newy(OneChunk::from(&pkt_body_v6[..])).unwrap())
    });
    c.bench_function("parse-udp", |b| {
        b.iter(|| ValidUdp::parse(black_box(&pkt_body_v4[34..42])).unwrap())
    });
    c.bench_function("parse-stack-v4", |b| {
        b.iter(|| {
            Parsed::newy(OneChunk::from(black_box(&pkt_body_v4[..]))).unwrap()
        })
    });
    c.bench_function("parse-and-decr-v4", |b| {
        b.iter(|| {
            let mut a =
                Parsed::newy(OneChunk::from(black_box(&mut pkt_body_v4[..])))
                    .unwrap();
            let hdr = a.headers_mut();
            hdr.l4.set_destination(hdr.l4.destination() - 1);
        })
    });
    c.bench_function("parse-stack-v6", |b| {
        b.iter(|| {
            Parsed::newy(OneChunk::from(black_box(&pkt_body_v6[..]))).unwrap()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
