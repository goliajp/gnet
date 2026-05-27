//! Zero-dependency throughput benchmarks for `gnet-hex`.
//!
//! Run: `cargo bench -p gnet-hex`. Hand-rolled `std::time` harness — criterion
//! is an external dep, forbidden in the overlay.
//!
//! Hex codec is used wherever pubkeys cross a textual boundary: `gnet keygen`
//! output, `gnet join` request body, the coordinator's JSON envelopes, conf
//! file `private`/`peer` directives, and `gnet status` operator dumps. The
//! 32-byte pubkey is the common case (X25519 + 64 hex chars); the long form
//! is ML-KEM-768's encapsulation key (1184 bytes / 2368 hex chars).

use std::hint::black_box;
use std::time::Instant;

use gnet_hex::{decode, decode_32, encode};

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);
    println!("{name:<32} {ns_op:>10.2} ns/op");
}

fn main() {
    println!("gnet-hex codec — per-op latency\n");

    // 32 bytes: an X25519 pubkey (most common — every join/peer line).
    let key32 = [0xABu8; 32];
    let hex32 = encode(&key32);
    let iters = 1_000_000;

    bench("encode 32B → 64 hex chars", iters, || {
        let s = encode(black_box(&key32));
        black_box(s);
    });
    bench("decode_32 (64 hex → 32B)", iters, || {
        let k = decode_32(black_box(&hex32));
        black_box(k);
    });
    bench("decode 32B (generic Vec path)", iters, || {
        let v = decode(black_box(&hex32));
        black_box(v);
    });

    // ~1KB bytes: ML-KEM-768 ek (1184 bytes → 2368 hex chars). Once per join.
    let mlkem_ek = vec![0xCDu8; 1184];
    let hex_ek = encode(&mlkem_ek);
    bench("encode 1184B (mlkem ek)", iters / 100, || {
        let s = encode(black_box(&mlkem_ek));
        black_box(s);
    });
    bench("decode 1184B (mlkem ek)", iters / 100, || {
        let v = decode(black_box(&hex_ek));
        black_box(v);
    });
}
