//! Data-plane hot-path performance gates. Deliberately generous: they catch
//! order-of-magnitude regressions in the per-packet AEAD path without flaking
//! on slow or contended CI. Measured baselines live in BUDGETS.md.
//!
//! Also covers the per-handshake `x25519_base` (fixed-base public-key
//! derivation): the Edwards comb path replaces the Montgomery ladder for
//! handshake throughput and ships with a regression gate to keep it inside
//! its measured envelope.

use gnet_crypto::{aead, sha3, x25519};
use std::time::{Duration, Instant};

#[test]
fn aead_per_packet_roundtrip_within_budget() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = [0u8; 16];
    let mut pkt = vec![0u8; 1400];

    // warm caches / branch predictors before timing
    for _ in 0..2_000 {
        let tag = aead::seal_in_place(&key, &nonce, &aad, &mut pkt);
        aead::open_in_place(&key, &nonce, &aad, &mut pkt, &tag).unwrap();
    }

    let iters = 20_000u32;
    let start = Instant::now();
    for _ in 0..iters {
        let tag = aead::seal_in_place(&key, &nonce, &aad, &mut pkt);
        aead::open_in_place(&key, &nonce, &aad, &mut pkt, &tag).unwrap();
    }
    let per = start.elapsed() / iters;

    // Release baseline seal+open ~= 2.4 us (lx64 AVX2) / 2.9 us (Apple NEON)
    // per 1400 B packet. Unoptimized `cargo test` builds run the crypto ~60x
    // slower (~160 us), so the budget tracks the build mode. Either way it
    // catches a ~6-7x regression while tolerating slow / contended CI.
    let budget = if cfg!(debug_assertions) {
        Duration::from_micros(1000)
    } else {
        Duration::from_micros(20)
    };
    assert!(
        per < budget,
        "AEAD per-packet roundtrip too slow: {per:?} (budget {budget:?}); see BUDGETS.md"
    );
}

#[test]
fn x25519_basepoint_derivation_within_budget() {
    let scalar = [0x77u8; 32];

    // Warm caches / branch predictors before timing.
    for _ in 0..200 {
        let _ = x25519::x25519_base(&scalar);
    }

    let iters = 2_000u32;
    let start = Instant::now();
    for _ in 0..iters {
        let pk = x25519::x25519_base(std::hint::black_box(&scalar));
        let _ = std::hint::black_box(pk);
    }
    let per = start.elapsed() / iters;

    // Release baselines (width-5 Edwards comb, 52 windows × 16 entries):
    //   Apple Silicon  ~5.4 µs  (was ~6.3 µs at width-4)
    //   lx64 (x86_64)  ~9.9 µs  (was ~11.6 µs at width-4)
    // Both architectures dropped ~12–15 % from the width-5 table.
    // Debug runs ~50× slower; budget tracks the build mode.
    // See BUDGETS.md "x25519_base" row for calibration.
    let budget = if cfg!(debug_assertions) {
        Duration::from_micros(400)
    } else if cfg!(target_arch = "aarch64") {
        Duration::from_micros(6)
    } else {
        Duration::from_micros(11)
    };
    eprintln!("x25519_base per call: {per:?} (budget {budget:?})");
    assert!(
        per < budget,
        "x25519_base too slow: {per:?} (budget {budget:?}); see BUDGETS.md"
    );
}

#[test]
fn keccak_f_baseline_microbench() {
    // shake128(b"", 168B) = 1 absorb-padded-block + 1 keccak_f + 1 squeeze-block
    // (the squeeze of the first rate-block does not trigger an extra permutation).
    // So this approximates 1 keccak_f per call, plus byte-shuffling overhead.
    let mut out = [0u8; 168];

    // Warm caches.
    for _ in 0..2_000 {
        sha3::shake128(b"", &mut out);
    }

    let iters = if cfg!(debug_assertions) {
        20_000u32
    } else {
        200_000u32
    };
    let start = Instant::now();
    for _ in 0..iters {
        sha3::shake128(std::hint::black_box(b""), std::hint::black_box(&mut out));
    }
    let elapsed = start.elapsed();
    let per_call_ns = elapsed.as_nanos() as u64 / iters as u64;

    // Expected ballpark (release):
    //   Apple Silicon (NEON, M1/M2): ~180 ns/call (~1 permutation)
    //   lx64 x86_64 (AVX2 unused for scalar): ~280 ns/call
    // Used as a soft ceiling reference for sha3/neon_x4 work — knowing
    // single-permutation cost tells us how big the 4-way win can be.
    eprintln!("shake128(empty, 168B): {per_call_ns} ns/call (~= 1 keccak_f)");

    // Generous regression budget: 3× expected for slow CI.
    let budget_ns = if cfg!(debug_assertions) {
        30_000u64 // very loose for debug builds
    } else if cfg!(target_arch = "aarch64") {
        600u64
    } else {
        1000u64
    };
    assert!(
        per_call_ns < budget_ns,
        "keccak_f scalar baseline too slow: {per_call_ns} ns/call (budget {budget_ns} ns)"
    );
}
