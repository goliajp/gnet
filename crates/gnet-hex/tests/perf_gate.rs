//! Performance regression gate for `gnet-hex`, run under `cargo test`.
//!
//! Hex encode/decode runs every time a pubkey crosses a textual boundary
//! (`gnet keygen` / `gnet join` / `gnet status` / conf parser / coordinator
//! JSON). Per-op cost is bounded by the buffer size; the gate fires on the
//! 32-byte (X25519 pubkey) path because that's the one used per request.
//! See `BUDGETS.md` for the optimised baseline.

use std::hint::black_box;
use std::time::Instant;

use gnet_hex::{decode_32, encode};

const ITERS: u32 = 1_000_000;

#[test]
fn encode_32_within_budget() {
    let key = [0xABu8; 32];
    for _ in 0..ITERS / 8 {
        black_box(encode(&key));
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        black_box(encode(black_box(&key)));
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS);

    // ~150 ns/op observed on dev; 1500 ns/op budget = 10× headroom for
    // `cargo test` unoptimised + slow CI. Catches a 10× regression.
    assert!(
        ns < 1500.0,
        "encode 32B {ns:.0} ns/op exceeds the 1500 ns/op budget"
    );
}

#[test]
fn decode_32_within_budget() {
    let key = [0xABu8; 32];
    let hex = encode(&key);
    for _ in 0..ITERS / 8 {
        black_box(decode_32(&hex));
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        black_box(decode_32(black_box(&hex)));
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS);

    assert!(
        ns < 1500.0,
        "decode_32 {ns:.0} ns/op exceeds the 1500 ns/op budget"
    );
}
