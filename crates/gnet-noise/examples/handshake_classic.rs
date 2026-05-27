//! Drive a full classical `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake
//! between an initiator and responder, then exchange one transport packet
//! each way. No I/O — the example treats the handshake as a pure function
//! over bytes. For the post-quantum hybrid variant (Noise_IK + ML-KEM-768)
//! see `HYBRID.md` and the `hybrid` module's tests.
//!
//! ```sh
//! cargo run -p gnet-noise --example handshake_classic
//! ```

use gnet_crypto::x25519;
use gnet_noise::handshake::{Initiator, Responder};

fn main() {
    // Both sides' long-term static keys (derived from a known scalar for
    // determinism; production code injects fresh OS entropy via gnet-rand).
    let init_static = [0x11u8; 32];
    let resp_static = [0x22u8; 32];
    let resp_static_pub = x25519::x25519_base(&resp_static);

    // Ephemerals are injected by the caller — this crate is RNG-free.
    let init_ephemeral = [0x33u8; 32];
    let resp_ephemeral = [0x44u8; 32];

    let mut ini = Initiator::new(init_static, resp_static_pub, init_ephemeral);
    let mut resp = Responder::new(resp_static, resp_ephemeral);

    let msg1 = ini.write_message_1(b"hello from initiator");
    println!("msg1: {} bytes on the wire", msg1.len());
    let payload1 = resp.read_message_1(&msg1).expect("msg1 authenticates");
    println!(
        "responder reads: {:?}",
        core::str::from_utf8(&payload1).unwrap()
    );

    let (msg2, mut resp_transport) =
        resp.write_message_2(b"hello from responder").expect("write msg2");
    println!("msg2: {} bytes on the wire", msg2.len());
    let (mut ini_transport, payload2) = ini.read_message_2(&msg2).expect("read msg2");
    println!(
        "initiator reads: {:?}",
        core::str::from_utf8(&payload2).unwrap()
    );

    // Transport packet, initiator -> responder.
    let ct = ini_transport.send.encrypt_with_ad(b"", b"ping");
    let pt = resp_transport
        .recv
        .decrypt_with_ad(b"", &ct)
        .expect("transport authenticates");
    assert_eq!(&pt, b"ping");
    println!("transport ok: 'ping' decrypted on the responder side");
}
