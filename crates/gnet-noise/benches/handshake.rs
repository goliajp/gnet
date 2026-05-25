//! Zero-dependency throughput benchmark for the Noise_IK and hybrid handshakes.
//! Run with `cargo bench -p mesh-noise`.

use std::hint::black_box;
use std::time::Instant;

use gnet_crypto::{mlkem, x25519};
use gnet_noise::handshake::{Initiator, Responder};
use gnet_noise::hybrid::{HybridInitiator, HybridResponder};

fn base() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
}

/// One complete initiator<->responder handshake (msg1, msg2, split).
fn one_handshake(responder_static: &[u8; 32], responder_pub: &[u8; 32]) {
    let mut ini = Initiator::new([0x11u8; 32], *responder_pub, [0x33u8; 32]);
    let mut resp = Responder::new(*responder_static, [0x44u8; 32]);
    let msg1 = ini.write_message_1(b"");
    resp.read_message_1(&msg1).unwrap();
    let (msg2, resp_tp) = resp.write_message_2(b"").unwrap();
    let (ini_tp, _) = ini.read_message_2(&msg2).unwrap();
    black_box((ini_tp.send, resp_tp.recv));
}

/// One complete hybrid (Noise_IK + ML-KEM-768) handshake.
fn one_hybrid_handshake(
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

fn main() {
    let responder_static = [0x22u8; 32];
    let responder_pub = x25519::x25519(&responder_static, &base());
    const ITERS: u32 = 5000;

    for _ in 0..200 {
        one_handshake(&responder_static, &responder_pub);
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        one_handshake(black_box(&responder_static), black_box(&responder_pub));
    }
    let ns = start.elapsed().as_secs_f64() * 1.0e9 / f64::from(ITERS);
    println!(
        "noise_ik full handshake   {:>10.0} ops/s   {ns:>12.1} ns/op",
        1.0e9 / ns
    );

    let (resp_ek, resp_dk) = mlkem::keygen(&[0x01u8; 32], &[0x02u8; 32]);
    const HITERS: u32 = 1000;
    for _ in 0..50 {
        one_hybrid_handshake(&responder_static, &responder_pub, &resp_ek, &resp_dk);
    }
    let start = Instant::now();
    for _ in 0..HITERS {
        one_hybrid_handshake(
            black_box(&responder_static),
            black_box(&responder_pub),
            black_box(&resp_ek),
            black_box(&resp_dk),
        );
    }
    let ns = start.elapsed().as_secs_f64() * 1.0e9 / f64::from(HITERS);
    println!(
        "hybrid ML-KEM handshake   {:>10.0} ops/s   {ns:>12.1} ns/op",
        1.0e9 / ns
    );
}
