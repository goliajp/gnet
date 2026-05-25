//! Zero-dependency throughput benchmarks for `gnet-crypto`.
//!
//! Run: `cargo bench -p gnet-crypto`. We use a hand-rolled `std::time`
//! harness because criterion is an external dependency (forbidden here).
//!
//! Baseline target: meet or beat best-in-class implementations
//! (ring / *-dalek / RustCrypto / libsodium) on the same hardware. These
//! numbers are the yardstick we polish against, not a one-time check.

use std::hint::black_box;
use std::time::Instant;

use gnet_crypto::{aead, blake2s, chacha20, mlkem, poly1305, x25519};

/// Time `f` over `iters` iterations (each processing `bytes` bytes) and
/// print throughput + per-op latency.
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
    println!("{name:<26} {mib_s:>10.1} MiB/s   {ns_op:>12.1} ns/op");
}

/// Time a per-operation `f` over `iters` iterations; print ops/s + latency.
/// For primitives measured per call (key exchange, KEM), not per byte.
fn bench_ops(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = start.elapsed().as_secs_f64() * 1.0e9 / f64::from(iters);
    println!("{name:<26} {:>10.0} ops/s   {ns:>12.1} ns/op", 1.0e9 / ns);
}

fn main() {
    const SIZE: usize = 64 * 1024;
    const ITERS: u32 = 4096;

    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let poly_key = [0x13u8; 32];
    let mut buf = vec![0u8; SIZE];

    println!(
        "gnet-crypto throughput  ({} KiB/op, {ITERS} iters; target >= ring/dalek/RustCrypto/libsodium)",
        SIZE / 1024
    );

    bench("chacha20 apply_keystream", SIZE, ITERS, || {
        chacha20::apply_keystream(&key, 1, &nonce, &mut buf);
        black_box(&buf);
    });
    bench("poly1305 mac", SIZE, ITERS, || {
        black_box(poly1305::poly1305(&poly_key, black_box(&buf)));
    });
    bench("blake2s hash", SIZE, ITERS, || {
        black_box(blake2s::hash(32, black_box(&buf)));
    });
    // seal allocates output + mac buffers each call, so this includes
    // allocation overhead, not just cipher+mac throughput.
    let aad = [0u8; 16];
    bench("chacha20poly1305 seal", SIZE, ITERS, || {
        black_box(aead::seal(&key, &nonce, &aad, black_box(&buf)));
    });
    // allocation-free bulk seal (the MAC runs over the cipher output in place).
    let mut sbuf = vec![0u8; SIZE];
    bench("aead seal_in_place 64K", SIZE, ITERS, || {
        black_box(aead::seal_in_place(
            &key,
            &nonce,
            &aad,
            black_box(&mut sbuf),
        ));
    });
    // per-packet (typical MTU) seal — the tunnel's actual per-op workload,
    // where the one-time-key ChaCha block + call overhead are not amortized.
    const PKT: usize = 1400;
    let mut pkt = vec![0u8; PKT];
    bench("aead seal_in_place 1400B", PKT, ITERS * 8, || {
        black_box(aead::seal_in_place(&key, &nonce, &aad, black_box(&mut pkt)));
    });

    // per-operation primitives below run once per handshake, not per packet.
    let sk = [0x11u8; 32];
    let mut base = [0u8; 32];
    base[0] = 9;
    bench_ops("x25519 scalarmult", 2000, || {
        black_box(x25519::x25519(black_box(&sk), black_box(&base)));
    });

    // ML-KEM-768: the post-quantum KEM in the hybrid handshake.
    let d = [0x01u8; 32];
    let z = [0x02u8; 32];
    let m = [0x03u8; 32];
    let (ek, dk) = mlkem::keygen(&d, &z);
    let (_ss, ct) = mlkem::encaps(&ek, &m);
    bench_ops("ml-kem-768 keygen", 1000, || {
        black_box(mlkem::keygen(black_box(&d), black_box(&z)));
    });
    bench_ops("ml-kem-768 encaps", 1000, || {
        black_box(mlkem::encaps(black_box(&ek), black_box(&m)));
    });
    bench_ops("ml-kem-768 decaps", 1000, || {
        black_box(mlkem::decaps(black_box(&dk), black_box(&ct)));
    });
}
