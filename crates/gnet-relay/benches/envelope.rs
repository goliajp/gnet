//! Zero-dependency throughput benchmarks for `mesh-relay`.
//!
//! Run: `cargo bench -p mesh-relay`. Hand-rolled `std::time` harness — criterion
//! is an external dependency, forbidden in the overlay (same rule as
//! `mesh-crypto`). The envelope sits on the relay data path: every relayed
//! packet is wrapped on send (`encode_into`) and routed (`dst_key`) + unwrapped
//! (`decode`) on receive, so these are per-packet hot-path costs.

use std::hint::black_box;
use std::time::Instant;

/// Time `f` over `iters` iterations (each touching `bytes` bytes) and print
/// throughput + per-op latency.
fn bench(name: &str, bytes: usize, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed().as_secs_f64();
    let total = bytes as f64 * f64::from(iters);
    let mib_s = total / (1024.0 * 1024.0) / elapsed;
    let ns_op = elapsed * 1.0e9 / f64::from(iters);
    println!("{name:<28} {mib_s:>10.1} MiB/s   {ns_op:>10.1} ns/op");
}

fn main() {
    let src = [7u8; gnet_relay::KEY_LEN];
    let dst = [9u8; gnet_relay::KEY_LEN];
    // a 1400-byte inner transport datagram (typical MTU-bound packet)
    let inner = [0x5au8; 1400];
    let mut out = [0u8; 2048];
    let iters = 5_000_000;
    let total = gnet_relay::HEADER_LEN + inner.len();

    println!("mesh-relay envelope — per-packet hot path\n");

    bench("encode_into 1400B", total, iters, || {
        let n = gnet_relay::encode_into(&mut out, &src, &dst, black_box(&inner)).unwrap();
        // read the written buffer back so the optimizer can't elide the copy
        black_box(&out[..n]);
    });

    let n = gnet_relay::encode_into(&mut out, &src, &dst, &inner).unwrap();
    let env = out[..n].to_vec();
    bench("decode 1400B", total, iters, || {
        let (s, d, i) = gnet_relay::decode(black_box(&env)).unwrap();
        black_box((s, d, i));
    });
    bench("dst_key (route only)", gnet_relay::KEY_LEN, iters, || {
        let d = gnet_relay::dst_key(black_box(&env)).unwrap();
        black_box(d);
    });
}
