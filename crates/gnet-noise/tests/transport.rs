//! Integration: a full Noise_IK handshake followed by sustained transport —
//! exercises per-direction nonce sequencing over many messages, empty/large
//! payloads, and malformed handshake-input rejection.

use gnet_crypto::x25519;
use gnet_noise::handshake::{Initiator, Responder, Transport};

fn base() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
}

/// Run a complete handshake and return both endpoints' transports.
fn established() -> (Transport, Transport) {
    let r_static = [0x22u8; 32];
    let r_pub = x25519::x25519(&r_static, &base());
    let mut ini = Initiator::new([0x11u8; 32], r_pub, [0x33u8; 32]);
    let mut resp = Responder::new(r_static, [0x44u8; 32]);

    let msg1 = ini.write_message_1(b"");
    resp.read_message_1(&msg1).unwrap();
    let (msg2, resp_tp) = resp.write_message_2(b"").unwrap();
    let (ini_tp, _) = ini.read_message_2(&msg2).unwrap();
    (ini_tp, resp_tp)
}

#[test]
fn sustained_bidirectional_transport() {
    let (mut ini, mut resp) = established();
    for i in 0..256u32 {
        let a = format!("ini->resp #{i}");
        let ct = ini.send.encrypt_with_ad(b"", a.as_bytes());
        assert_eq!(
            resp.recv.decrypt_with_ad(b"", &ct).as_deref(),
            Some(a.as_bytes())
        );

        let b = format!("resp->ini #{i}");
        let ct = resp.send.encrypt_with_ad(b"", b.as_bytes());
        assert_eq!(
            ini.recv.decrypt_with_ad(b"", &ct).as_deref(),
            Some(b.as_bytes())
        );
    }
}

#[test]
fn empty_and_large_payloads() {
    let (mut ini, mut resp) = established();

    let empty = ini.send.encrypt_with_ad(b"", b"");
    assert_eq!(
        resp.recv.decrypt_with_ad(b"", &empty).as_deref(),
        Some(&b""[..])
    );

    let big = vec![0xa5u8; 4000];
    let ct = ini.send.encrypt_with_ad(b"hdr", &big);
    assert_eq!(
        resp.recv.decrypt_with_ad(b"hdr", &ct).as_deref(),
        Some(big.as_slice())
    );
}

#[test]
fn responder_rejects_short_message_1() {
    let mut resp = Responder::new([0x22u8; 32], [0x44u8; 32]);
    // both are below the minimum length and rejected before any state change
    assert!(resp.read_message_1(&[]).is_none());
    assert!(resp.read_message_1(&[0u8; 10]).is_none());
}

#[test]
fn responder_rejects_garbage_message_1() {
    let mut resp = Responder::new([0x22u8; 32], [0x44u8; 32]);
    // long enough to pass the length gate, but fails AEAD authentication
    assert!(resp.read_message_1(&[0xabu8; 200]).is_none());
}
