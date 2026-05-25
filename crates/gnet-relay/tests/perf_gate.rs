//! Performance regression gate for `gnet-relay`, run under `cargo test`.
//!
//! The envelope is on the relay data path, so a regression here costs every
//! relayed packet. We assert `encode_into` stays within a generous budget —
//! enough to catch a gross regression while tolerating the unoptimized
//! `cargo test` build and slow/contended CI. See `BUDGETS.md` for the
//! optimized baseline (~18 ns/op).

use std::hint::black_box;
use std::time::Instant;

#[test]
fn encode_into_stays_within_budget() {
    let src = [7u8; gnet_relay::KEY_LEN];
    let dst = [9u8; gnet_relay::KEY_LEN];
    let inner = [0x5au8; 1400];
    let mut out = [0u8; 2048];
    let iters = 100_000u32;

    for _ in 0..iters / 8 {
        let n = gnet_relay::encode_into(&mut out, &src, &dst, &inner).unwrap();
        black_box(&out[..n]);
    }
    let start = Instant::now();
    for _ in 0..iters {
        let n = gnet_relay::encode_into(&mut out, &src, &dst, black_box(&inner)).unwrap();
        black_box(&out[..n]);
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);

    // optimized baseline ~18 ns/op; allow ~55x headroom for debug + slow CI.
    assert!(
        ns_op < 1000.0,
        "encode_into {ns_op:.0} ns/op exceeds the 1000 ns/op budget"
    );
}
