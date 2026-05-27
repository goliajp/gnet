//! Performance regression gate for `gnet-rand`, run under `cargo test`.
//!
//! `random_32` is the per-handshake entropy draw (X25519 ephemeral scalars);
//! `random_u32` runs per rx-index / probe txid / dial jitter and is therefore
//! called several times per handshake. We assert the warm-cache per-call cost
//! stays under a generous budget — enough to catch a gross regression while
//! tolerating the unoptimized `cargo test` build, slow CI, and the
//! `/dev/urandom` syscall variance. See `BUDGETS.md` for the optimized
//! baseline.

use std::hint::black_box;
use std::time::Instant;

use gnet_rand::{random_32, random_u32};

const ITERS: u32 = 100_000;

#[test]
fn random_32_within_budget() {
    // warm-up amortises the first-call `/dev/urandom` open + page-fault path.
    for _ in 0..ITERS / 8 {
        black_box(random_32());
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        black_box(random_32());
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS);

    // 50 µs/op is ~10× the observed P95 on dev hardware (~5 µs/op for cold
    // urandom on macOS/Linux). 3× CI headroom from there.
    assert!(
        ns < 50_000.0,
        "random_32 {ns:.0} ns/op exceeds the 50_000 ns/op budget"
    );
}

#[test]
fn random_u32_within_budget() {
    for _ in 0..ITERS / 8 {
        black_box(random_u32());
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        black_box(random_u32());
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS);

    // Same syscall as random_32; budget identical for simplicity.
    assert!(
        ns < 50_000.0,
        "random_u32 {ns:.0} ns/op exceeds the 50_000 ns/op budget"
    );
}
