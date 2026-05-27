//! Data-plane hot-path performance gates. Deliberately generous: they catch
//! order-of-magnitude regressions in the per-packet AEAD path without flaking
//! on slow or contended CI. Measured baselines live in BUDGETS.md.
//!
//! Also covers the per-handshake `x25519_base` (fixed-base public-key
//! derivation): the Edwards comb path replaces the Montgomery ladder for
//! handshake throughput and ships with a regression gate to keep it inside
//! its measured envelope.

use gnet_crypto::{aead, x25519};
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

    // Release baselines: Apple Silicon ~6.3 µs (NEON, within ~1.5× of
    // dalek), lx64 (x86_64 AVX2) ~11.6 µs (same field code, ~2× slower
    // on x86 like the rest of the X25519 path). Debug runs ~50× slower.
    // See BUDGETS.md "x25519_base" row for calibration.
    let budget = if cfg!(debug_assertions) {
        Duration::from_micros(400)
    } else if cfg!(target_arch = "aarch64") {
        Duration::from_micros(7)
    } else {
        Duration::from_micros(14)
    };
    eprintln!("x25519_base per call: {per:?} (budget {budget:?})");
    assert!(
        per < budget,
        "x25519_base too slow: {per:?} (budget {budget:?}); see BUDGETS.md"
    );
}
