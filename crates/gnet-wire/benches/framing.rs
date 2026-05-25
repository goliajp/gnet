//! Zero-dependency throughput benchmarks for `gnet-wire`.
//!
//! Run: `cargo bench -p gnet-wire`. Hand-rolled `std::time` harness — criterion
//! is an external dependency, forbidden in the overlay (same rule as
//! `gnet-crypto`). The transport-header stamp/read is the per-packet hot path
//! (every datagram); `frame`/`parse` and the address codec are handshake- /
//! discovery-rate, measured here for completeness.

use std::hint::black_box;
use std::time::Instant;

use gnet_wire::{
    Kind, TRANSPORT_HEADER, counter, decode_addr, encode_addr, frame, index, parse, put_counter,
    put_index,
};

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);
    println!("{name:<28} {ns_op:>10.2} ns/op");
}

fn main() {
    println!("gnet-wire framing — per-op latency\n");

    // hot path: stamp + read the transport header on every packet
    let mut dg = [0u8; TRANSPORT_HEADER + 1400];
    dg[0] = Kind::Transport as u8;
    let iters = 50_000_000;

    bench("put_index + put_counter", iters, || {
        put_index(black_box(&mut dg), 0xDEAD_BEEF);
        put_counter(&mut dg, 0x0102_0304_0506_0708);
        black_box(&dg[..TRANSPORT_HEADER]);
    });
    bench("index + counter (read)", iters, || {
        let i = index(black_box(&dg));
        let c = counter(black_box(&dg));
        black_box((i, c));
    });

    // handshake path: frame an owned datagram + parse it back
    let body = [0xABu8; 96];
    bench("frame (owned, handshake)", iters / 10, || {
        let d = frame(Kind::HandshakeInit, black_box(&body));
        black_box(d);
    });
    let framed = frame(Kind::HandshakeInit, &body);
    bench("parse", iters, || {
        let p = parse(black_box(&framed));
        black_box(p);
    });

    // endpoint-discovery path: socket-address codec
    let addr = "203.0.113.7:50000".parse().unwrap();
    bench("encode_addr (v4)", iters / 10, || {
        let mut out = Vec::with_capacity(8);
        encode_addr(&mut out, black_box(addr));
        black_box(out);
    });
    let mut enc = Vec::new();
    encode_addr(&mut enc, addr);
    bench("decode_addr (v4)", iters, || {
        let d = decode_addr(black_box(&enc));
        black_box(d);
    });
}
