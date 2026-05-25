//! Performance regression gate for `gnet-noise`, run under `cargo test`.
//!
//! The Noise_IK handshake runs once per session establishment (a warm path:
//! several X25519 DHs plus the symmetric ratchet). A regression here slows every
//! new connection. We assert it stays within a generous budget — enough to catch
//! a gross regression while tolerating the unoptimized `cargo test` build and
//! slow CI. See `BUDGETS.md` for the optimized baseline.

use std::hint::black_box;
use std::time::Instant;

use gnet_crypto::{mlkem, x25519};
use gnet_noise::handshake::{Initiator, Responder};
use gnet_noise::hybrid::{HybridInitiator, HybridResponder};

/// X25519 base point.
fn base() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
}

/// One complete initiator<->responder Noise_IK handshake (msg1, msg2, split).
fn run_handshake(responder_static: &[u8; 32], responder_pub: &[u8; 32]) {
    let mut ini = Initiator::new([0x11u8; 32], *responder_pub, [0x33u8; 32]);
    let mut resp = Responder::new(*responder_static, [0x44u8; 32]);
    let msg1 = ini.write_message_1(b"");
    resp.read_message_1(&msg1).unwrap();
    let (msg2, resp_tp) = resp.write_message_2(b"").unwrap();
    let (ini_tp, _) = ini.read_message_2(&msg2).unwrap();
    black_box((ini_tp.send, resp_tp.recv));
}

#[test]
fn noise_ik_handshake_within_budget() {
    // generous budget for the unoptimized cargo-test build + slow CI; measured
    // ~3.6 ms (lx64) / ~4.1 ms (mac) in the cargo-test build, vs a ~250–480 µs
    // optimized baseline (see BUDGETS.md). 20 ms gives ~5x headroom.
    const BUDGET_US: f64 = 20_000.0;

    let responder_static = [0x22u8; 32];
    let responder_pub = x25519::x25519(&responder_static, &base());
    let iters = 500u32;

    for _ in 0..50 {
        run_handshake(&responder_static, &responder_pub);
    }
    let start = Instant::now();
    for _ in 0..iters {
        run_handshake(black_box(&responder_static), black_box(&responder_pub));
    }
    let us = start.elapsed().as_secs_f64() * 1e6 / f64::from(iters);
    eprintln!("Noise_IK handshake: {us:.0} µs/op (cargo-test build)");

    assert!(
        us < BUDGET_US,
        "Noise_IK handshake {us:.0} µs/op exceeds the {BUDGET_US:.0} µs/op budget"
    );
}

/// One complete hybrid (Noise_IK + ML-KEM-768) handshake.
fn run_hybrid_handshake(
    resp_static: &[u8; 32],
    resp_pub: &[u8; 32],
    resp_ek: &[u8],
    resp_dk: &[u8],
) {
    let mut ini =
        HybridInitiator::new([0x11u8; 32], *resp_pub, resp_ek, [0x33u8; 32], [0x55u8; 32]);
    let mut resp = HybridResponder::new(*resp_static, resp_ek, resp_dk, [0x44u8; 32]);
    let msg1 = ini.write_message_1(b"");
    resp.read_message_1(&msg1).unwrap();
    let (msg2, resp_tp) = resp.write_message_2(b"").unwrap();
    let (ini_tp, _) = ini.read_message_2(&msg2).unwrap();
    black_box((ini_tp.send, resp_tp.recv));
}

#[test]
fn hybrid_handshake_within_budget() {
    // the hybrid handshake adds an ML-KEM-768 encaps + decaps on top of
    // Noise_IK. Measured ~8.0 ms (lx64) / ~7.1 ms (mac) in the cargo-test
    // build, vs a ~306–612 µs optimized baseline. 40 ms gives ~5x headroom
    // (matching the Noise_IK gate). See BUDGETS.md.
    const BUDGET_US: f64 = 40_000.0;

    let resp_static = [0x22u8; 32];
    let resp_pub = x25519::x25519(&resp_static, &base());
    let (resp_ek, resp_dk) = mlkem::keygen(&[0x01u8; 32], &[0x02u8; 32]);
    let iters = 200u32;

    for _ in 0..20 {
        run_hybrid_handshake(&resp_static, &resp_pub, &resp_ek, &resp_dk);
    }
    let start = Instant::now();
    for _ in 0..iters {
        run_hybrid_handshake(
            black_box(&resp_static),
            black_box(&resp_pub),
            black_box(&resp_ek),
            black_box(&resp_dk),
        );
    }
    let us = start.elapsed().as_secs_f64() * 1e6 / f64::from(iters);
    eprintln!("hybrid handshake: {us:.0} µs/op (cargo-test build)");

    assert!(
        us < BUDGET_US,
        "hybrid handshake {us:.0} µs/op exceeds the {BUDGET_US:.0} µs/op budget"
    );
}
