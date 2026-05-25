//! Zero-dependency benchmarks for `gnet-punch`. Hand-rolled `std::time` harness
//! (no criterion). The rendezvous codec + state transitions are setup-rate (a
//! few per punch), not per-packet, so this tracks correctness-of-cost rather
//! than a data-plane budget.

use std::hint::black_box;
use std::time::Instant;

use gnet_punch::{PunchState, decode_connect, decode_sync, encode_connect, encode_sync};

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..(iters / 8).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_op = start.elapsed().as_secs_f64() * 1e9 / f64::from(iters);
    println!("{name:<26} {ns_op:>10.2} ns/op");
}

fn main() {
    println!("gnet-punch rendezvous — per-op latency\n");

    let origin = [7u8; 32];
    let target = [9u8; 32];
    let ep = "203.0.113.5:41000".parse().unwrap();
    let iters = 5_000_000;

    bench("encode_connect", iters, || {
        black_box(encode_connect(black_box(&origin), &target, ep));
    });
    let cbody = encode_connect(&origin, &target, ep);
    bench("decode_connect", iters, || {
        black_box(decode_connect(black_box(&cbody)));
    });
    bench("encode_sync", iters, || {
        black_box(encode_sync(black_box(&origin), &target));
    });
    let sbody = encode_sync(&origin, &target);
    bench("decode_sync", iters, || {
        black_box(decode_sync(black_box(&sbody)));
    });
    bench("on_reply (rtt measure)", iters, || {
        let mut st = PunchState::Connecting {
            sent_at: Instant::now(),
        };
        black_box(st.on_reply(black_box(ep), Instant::now()));
    });
}
