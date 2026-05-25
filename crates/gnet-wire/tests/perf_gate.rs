//! Performance regression gate for `gnet-wire`, run under `cargo test`.
//!
//! The transport-header stamp + read happens on every packet, so a regression
//! here costs the whole data plane. We assert it stays within a generous budget
//! — enough to catch a gross regression while tolerating the unoptimized
//! `cargo test` build and slow CI. See `BUDGETS.md` for the optimized baseline.

use std::hint::black_box;
use std::time::Instant;

use gnet_wire::{Kind, TRANSPORT_HEADER, counter, index, put_counter, put_index};

#[test]
fn transport_header_stamp_read_within_budget() {
    let mut dg = [0u8; TRANSPORT_HEADER + 1400];
    dg[0] = Kind::Transport as u8;
    let iters = 1_000_000u32;

    for _ in 0..iters / 8 {
        put_index(&mut dg, 1);
        put_counter(&mut dg, 1);
    }
    let start = Instant::now();
    for _ in 0..iters {
        put_index(black_box(&mut dg), 0xDEAD_BEEF);
        put_counter(&mut dg, 0x0102_0304_0506_0708);
        let i = index(black_box(&dg));
        let c = counter(black_box(&dg));
        black_box((i, c));
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);

    assert!(
        ns < 500.0,
        "transport header stamp+read {ns:.0} ns/op exceeds the 500 ns/op budget"
    );
}
