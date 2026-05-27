//! Zero-dependency throughput benchmarks for `gnet-rand`.
//!
//! Run: `cargo bench -p gnet-rand`. Hand-rolled `std::time` harness — criterion
//! is an external dep, forbidden in the overlay (same rule as `gnet-crypto`).
//!
//! What we measure here matters because every Noise handshake and every
//! per-peer index needs fresh entropy: the daemon calls `random_32` per
//! ephemeral X25519 scalar and `random_u32` per rx-index assignment. The
//! syscall + file-open cost is the floor — keep `random_32` < a few µs/op
//! on commodity hardware so a handshake's ~5 entropy draws are a rounding
//! error next to the AEAD + ML-KEM math.

use std::hint::black_box;
use std::time::Instant;

use gnet_rand::{fill, random_32, random_u32};

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    // warm-up: amortises any first-call cost (urandom open path, page faults)
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);
    println!("{name:<28} {ns_op:>12.0} ns/op");
}

fn main() {
    println!("gnet-rand entropy draw — per-op latency\n");

    // 32 bytes: one X25519 scalar, the per-handshake static-cost item.
    bench("random_32 (handshake)", 100_000, || {
        let k = random_32();
        black_box(k);
    });

    // 4 bytes: rx_index / probe txid / dial jitter — multiple per handshake.
    bench("random_u32 (per-op tags)", 100_000, || {
        let n = random_u32();
        black_box(n);
    });

    // raw fill into a stack buffer — exercises the syscall path with no
    // intermediate allocation. 32 bytes matches `random_32`; the gap between
    // this row and `random_32` is the copy-out overhead.
    let mut buf = [0u8; 32];
    bench("fill 32B (stack buf)", 100_000, || {
        fill(black_box(&mut buf));
        black_box(&buf);
    });

    // 1 KB fill — used by ML-KEM keygen-from-entropy paths.
    let mut big = [0u8; 1024];
    bench("fill 1024B (mlkem keygen)", 10_000, || {
        fill(black_box(&mut big));
        black_box(&big);
    });
}
