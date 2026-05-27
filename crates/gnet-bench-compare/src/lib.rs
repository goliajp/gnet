//! Common bench helpers shared by every cross-ecosystem comparison bench.
//!
//! Each `benches/<topic>.rs` imports these and uses them to print a
//! side-by-side `gnet` vs. SOTA-competitor table. NOT a production crate —
//! external crypto crates are pulled here *only* to put numbers next to ours.
//! The gnet stack itself stays zero-dep.

#![forbid(unsafe_code)]

use std::hint::black_box;
use std::time::Instant;

/// Time `f` over `iters` iterations, after `iters/8` warm-up calls. Returns the
/// average ns/op so callers can use it as a baseline for `bench_vs`.
pub fn bench(name: &str, iters: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);
    println!("  {name:<40} {ns_op:>12.2} ns/op");
    ns_op
}

/// Time `f` and annotate the result with a relative multiplier vs `baseline`,
/// so the reader sees at a glance whether the competitor is faster or slower.
pub fn bench_vs(name: &str, baseline_ns_op: f64, iters: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);
    let rel = ns_op / baseline_ns_op;
    let arrow = if rel < 1.0 { "↑ faster" } else { "↓ slower" };
    println!(
        "  {name:<40} {ns_op:>12.2} ns/op   {rel:>5.2}× ({arrow})"
    );
    ns_op
}

/// Print a section heading with an underline of the same visible width.
pub fn section(title: &str) {
    println!("\n{title}");
    println!("{}", "─".repeat(title.chars().count()));
}

/// Wrap a value in `black_box` so the optimiser cannot fold the bench body.
/// Thin alias to keep each bench's call sites readable.
pub fn opaque<T>(v: T) -> T {
    black_box(v)
}
