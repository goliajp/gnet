//! Performance regression gate for `gnet-punch`, run under `cargo test`.
//!
//! The rendezvous codec is setup-rate (a few calls per punch), not per-packet,
//! so the budget is generous — it catches a gross regression while tolerating
//! the unoptimized `cargo test` build and slow CI. See `BUDGETS.md` for the
//! optimized baseline.

use std::hint::black_box;
use std::time::Instant;

use gnet_punch::encode_connect;

#[test]
fn encode_connect_within_budget() {
    let origin = [7u8; 32];
    let target = [9u8; 32];
    let ep = "203.0.113.5:41000".parse().unwrap();
    let iters = 200_000u32;

    for _ in 0..iters / 8 {
        black_box(encode_connect(&origin, &target, ep));
    }
    let start = Instant::now();
    for _ in 0..iters {
        black_box(encode_connect(black_box(&origin), &target, ep));
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);

    assert!(
        ns < 2000.0,
        "encode_connect {ns:.0} ns/op exceeds the 2000 ns/op budget"
    );
}
