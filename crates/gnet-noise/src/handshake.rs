//! The `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake (the pattern
//! WireGuard is based on).
//!
//! ```text
//! IK:
//!   <- s                       (pre-message: responder static, known to initiator)
//!   ...
//!   -> e, es, s, ss            (message 1)
//!   <- e, ee, se               (message 2)
//! ```
//!
//! Ephemeral private keys are **injected** by the caller, not generated
//! here: this keeps the crate free of an RNG dependency and makes the
//! handshake deterministic-testable. The caller (or a future `gnet-rand`)
//! is responsible for supplying fresh, secret ephemerals.

use crate::cipher_state::CipherState;
use crate::replay::ReplayWindow;
use crate::symmetric_state::SymmetricState;
use gnet_crypto::x25519;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const TAG_LEN: usize = 16;

/// A completed handshake's transport cipher states, plus anti-replay state for
/// the receive direction.
pub struct Transport {
    /// Cipher for messages we send.
    pub send: CipherState,
    /// Cipher for messages we receive.
    pub recv: CipherState,
    /// Anti-replay window for received packet counters.
    recv_window: ReplayWindow,
}

impl Transport {
    /// Build a transport from the split cipher states, with a fresh anti-replay
    /// window. Used by the handshake state machines once keys are derived.
    pub(crate) fn new(send: CipherState, recv: CipherState) -> Self {
        Self {
            send,
            recv,
            recv_window: ReplayWindow::new(),
        }
    }

    /// The counter the next sent packet will use; stamp it on the wire so the
    /// peer can decrypt and replay-check it via [`recv_at`](Self::recv_at).
    pub fn send_counter(&self) -> u64 {
        self.send.counter()
    }

    /// Decrypt a received transport packet carrying an explicit `counter`,
    /// rejecting replays and packets older than the anti-replay window.
    /// Out-of-order delivery within the window is accepted. On success the
    /// plaintext occupies `buf[..len - 16]` and that length is returned.
    pub fn recv_at(
        &mut self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
    ) -> Option<usize> {
        // decrypt first: the counter is the AEAD nonce, so a forged counter
        // fails authentication here and never reaches the replay check.
        let plain = self.recv.decrypt_in_place_at(counter, ad, buf, len)?;
        if !self.recv_window.accept(counter) {
            return None; // authentic but replayed or too old
        }
        Some(plain)
    }
}

#[inline]
fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519::x25519(secret, public)
}

/// Test-only single-key derivation helper. The production code paths
/// (`Initiator::new` / `Responder::new`) call
/// [`x25519::x25519_base_pair`] to amortize one shared field inversion
/// across the static + ephemeral pair.
#[cfg(test)]
#[inline]
fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    x25519::x25519_base(secret)
}

/// The handshake initiator. Knows the responder's static public key.
pub struct Initiator {
    sym: SymmetricState,
    s_priv: [u8; 32],
    s_pub: [u8; 32],
    e_priv: [u8; 32],
    e_pub: [u8; 32],
    rs: [u8; 32],
}

impl Initiator {
    /// Create an initiator with its static private key, the responder's
    /// static public key, and an injected ephemeral private key.
    pub fn new(
        static_priv: [u8; 32],
        responder_static_pub: [u8; 32],
        ephemeral_priv: [u8; 32],
    ) -> Self {
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(&[]); // empty prologue
        sym.mix_hash(&responder_static_pub); // pre-message `s`
        // One shared finvert across both derivations — see
        // gnet_crypto::x25519::x25519_base_pair.
        let [s_pub, e_pub] = x25519::x25519_base_pair([&static_priv, &ephemeral_priv]);
        Self {
            s_pub,
            e_pub,
            s_priv: static_priv,
            e_priv: ephemeral_priv,
            rs: responder_static_pub,
            sym,
        }
    }

    /// Write handshake message 1 (`e, es, s, ss` + payload). One allocation:
    /// the returned `Vec` is sized exactly for the framed wire bytes.
    pub fn write_message_1(&mut self, payload: &[u8]) -> Vec<u8> {
        // Layout: e(32) || enc_s(32 + 16) || enc_payload(payload.len() + 16)
        let total = 32 + (32 + TAG_LEN) + (payload.len() + TAG_LEN);
        let mut msg = vec![0u8; total];

        // e
        self.sym.mix_hash(&self.e_pub);
        msg[0..32].copy_from_slice(&self.e_pub);

        // es
        self.sym.mix_key(&dh(&self.e_priv, &self.rs));

        // s (encrypted static)
        let s_off = 32;
        msg[s_off..s_off + 32].copy_from_slice(&self.s_pub);
        let n = self
            .sym
            .encrypt_and_hash_in_place(&mut msg[s_off..s_off + 32 + TAG_LEN], 32);
        debug_assert_eq!(n, 32 + TAG_LEN);

        // ss
        self.sym.mix_key(&dh(&self.s_priv, &self.rs));

        // payload (encrypted)
        let p_off = s_off + 32 + TAG_LEN;
        msg[p_off..p_off + payload.len()].copy_from_slice(payload);
        let n = self
            .sym
            .encrypt_and_hash_in_place(&mut msg[p_off..p_off + payload.len() + TAG_LEN], payload.len());
        debug_assert_eq!(n, payload.len() + TAG_LEN);

        msg
    }

    /// Read handshake message 2 (`e, ee, se` + payload), consuming the
    /// handshake and yielding the transport pair plus the responder payload.
    /// One allocation: the returned payload `Vec`.
    pub fn read_message_2(mut self, msg: &[u8]) -> Option<(Transport, Vec<u8>)> {
        if msg.len() < 32 + TAG_LEN {
            return None;
        }
        let re_pub: [u8; 32] = msg[..32].try_into().ok()?;
        // e
        self.sym.mix_hash(&re_pub);
        // ee
        self.sym.mix_key(&dh(&self.e_priv, &re_pub));
        // se = DH(initiator static, responder ephemeral)
        self.sym.mix_key(&dh(&self.s_priv, &re_pub));

        // payload (in-place decrypt into a Vec sized to the ciphertext)
        let ct_len = msg.len() - 32;
        let mut payload = vec![0u8; ct_len];
        payload.copy_from_slice(&msg[32..]);
        let pt_len = self.sym.decrypt_and_hash_in_place(&mut payload, ct_len)?;
        payload.truncate(pt_len);

        let (c1, c2) = self.sym.split();
        Some((Transport::new(c1, c2), payload))
    }
}

/// The handshake responder.
pub struct Responder {
    sym: SymmetricState,
    s_priv: [u8; 32],
    e_priv: [u8; 32],
    e_pub: [u8; 32],
    initiator_ephemeral: Option<[u8; 32]>,
    initiator_static: Option<[u8; 32]>,
}

impl Responder {
    /// Create a responder with its static private key and an injected
    /// ephemeral private key.
    pub fn new(static_priv: [u8; 32], ephemeral_priv: [u8; 32]) -> Self {
        // One shared finvert across both derivations.
        let [s_pub, e_pub] = x25519::x25519_base_pair([&static_priv, &ephemeral_priv]);
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(&[]); // empty prologue
        sym.mix_hash(&s_pub); // pre-message `s` (our own static)
        Self {
            s_priv: static_priv,
            e_pub,
            e_priv: ephemeral_priv,
            sym,
            initiator_ephemeral: None,
            initiator_static: None,
        }
    }

    /// The initiator's static public key, learned during
    /// [`read_message_1`](Self::read_message_1). `None` before message 1 is
    /// read. A multi-peer node uses this to match the handshake to a
    /// configured peer before replying.
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.initiator_static
    }

    /// Read handshake message 1 (`e, es, s, ss` + payload), returning the
    /// initiator's payload. Learns the initiator's static key. One allocation:
    /// the returned payload `Vec`.
    pub fn read_message_1(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        // e(32) + encrypted static(32+16) + payload(>=16 tag)
        if msg.len() < 32 + (32 + TAG_LEN) + TAG_LEN {
            return None;
        }
        let ie_pub: [u8; 32] = msg[..32].try_into().ok()?;
        self.initiator_ephemeral = Some(ie_pub);
        // e
        self.sym.mix_hash(&ie_pub);
        // es
        self.sym.mix_key(&dh(&self.s_priv, &ie_pub));
        // s (decrypt into a 48-byte stack buffer)
        let mut s_buf = [0u8; 32 + TAG_LEN];
        s_buf.copy_from_slice(&msg[32..32 + 32 + TAG_LEN]);
        let s_len = self.sym.decrypt_and_hash_in_place(&mut s_buf, 32 + TAG_LEN)?;
        if s_len != 32 {
            return None;
        }
        let is_pub: [u8; 32] = s_buf[..32].try_into().ok()?;
        self.initiator_static = Some(is_pub);
        // ss
        self.sym.mix_key(&dh(&self.s_priv, &is_pub));
        // payload (decrypt into a Vec sized to the ciphertext)
        let p_off = 32 + 32 + TAG_LEN;
        let p_ct_len = msg.len() - p_off;
        let mut payload = vec![0u8; p_ct_len];
        payload.copy_from_slice(&msg[p_off..]);
        let pt_len = self.sym.decrypt_and_hash_in_place(&mut payload, p_ct_len)?;
        payload.truncate(pt_len);
        Some(payload)
    }

    /// Write handshake message 2 (`e, ee, se` + payload), consuming the
    /// handshake and yielding the outgoing message plus the transport pair.
    /// One allocation: the returned `Vec`.
    pub fn write_message_2(mut self, payload: &[u8]) -> Option<(Vec<u8>, Transport)> {
        let ie = self.initiator_ephemeral?;
        let is = self.initiator_static?;
        // Layout: e(32) || enc_payload(payload.len() + 16)
        let total = 32 + payload.len() + TAG_LEN;
        let mut msg = vec![0u8; total];

        // e
        self.sym.mix_hash(&self.e_pub);
        msg[0..32].copy_from_slice(&self.e_pub);
        // ee
        self.sym.mix_key(&dh(&self.e_priv, &ie));
        // se = DH(initiator static, responder ephemeral)
        self.sym.mix_key(&dh(&self.e_priv, &is));
        // payload
        msg[32..32 + payload.len()].copy_from_slice(payload);
        let n = self
            .sym
            .encrypt_and_hash_in_place(&mut msg[32..32 + payload.len() + TAG_LEN], payload.len());
        debug_assert_eq!(n, payload.len() + TAG_LEN);

        let (c1, c2) = self.sym.split();
        // responder sends on the responder→initiator cipher (c2).
        Some((msg, Transport::new(c2, c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        // (initiator static, responder static, initiator ephemeral, responder ephemeral)
        ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32])
    }

    /// Profile-driven exploration of where Noise_IK handshake spends time.
    /// Splits the full handshake into the obvious phases (Initiator::new,
    /// write_message_1, Responder::new, read_message_1, write_message_2,
    /// read_message_2) and times each in isolation. Used to confirm
    /// whether the crypto kernel is at hardware ceiling or has a hidden
    /// hot spot like the byte_encode case in ML-KEM.
    ///
    /// Run: `cargo test --release -p gnet-noise --lib handshake::tests::ik_handshake_breakdown_microbench -- --ignored --nocapture`
    #[test]
    #[ignore = "informational microbench"]
    fn ik_handshake_breakdown_microbench() {
        use std::time::Instant;
        let (is, rs, ie, re) = keys();
        let rs_pub = public_of(&rs);

        // warm
        for _ in 0..50 {
            let mut ini = Initiator::new(is, rs_pub, ie);
            let m1 = ini.write_message_1(b"");
            let mut resp = Responder::new(rs, re);
            resp.read_message_1(&m1).unwrap();
            let (m2, _) = resp.write_message_2(b"").unwrap();
            let _ = ini.read_message_2(&m2).unwrap();
        }
        let iters = 5_000u32;

        let mut t_ini_new = 0u128;
        let mut t_w1 = 0u128;
        let mut t_resp_new = 0u128;
        let mut t_r1 = 0u128;
        let mut t_w2 = 0u128;
        let mut t_r2 = 0u128;
        let mut t_total = 0u128;

        for _ in 0..iters {
            let s_total = Instant::now();

            let s = Instant::now();
            let mut ini = Initiator::new(is, rs_pub, ie);
            t_ini_new += s.elapsed().as_nanos();

            let s = Instant::now();
            let m1 = ini.write_message_1(b"");
            t_w1 += s.elapsed().as_nanos();

            let s = Instant::now();
            let mut resp = Responder::new(rs, re);
            t_resp_new += s.elapsed().as_nanos();

            let s = Instant::now();
            resp.read_message_1(&m1).unwrap();
            t_r1 += s.elapsed().as_nanos();

            let s = Instant::now();
            let (m2, _) = resp.write_message_2(b"").unwrap();
            t_w2 += s.elapsed().as_nanos();

            let s = Instant::now();
            let _ = ini.read_message_2(&m2).unwrap();
            t_r2 += s.elapsed().as_nanos();

            t_total += s_total.elapsed().as_nanos();
        }

        let n = u128::from(iters);
        eprintln!("\nNoise_IK handshake breakdown ({iters} iters, ns/op):");
        eprintln!("  Initiator::new (2× x25519_base)  : {} ns", t_ini_new / n);
        eprintln!("  write_message_1 (1 DH + mix + AEAD): {} ns", t_w1 / n);
        eprintln!("  Responder::new  (2× x25519_base)  : {} ns", t_resp_new / n);
        eprintln!(
            "  read_message_1  (2 DH + AEAD decrypt + mix): {} ns",
            t_r1 / n
        );
        eprintln!(
            "  write_message_2 (2 DH + AEAD encrypt + mix): {} ns",
            t_w2 / n
        );
        eprintln!("  read_message_2  (2 DH + AEAD decrypt + mix): {} ns", t_r2 / n);
        eprintln!("  TOTAL handshake                  : {} ns", t_total / n);
        eprintln!(
            "  (sum of phases / total)          : {:.1}% (rest = Instant + flow overhead)",
            (t_ini_new + t_w1 + t_resp_new + t_r1 + t_w2 + t_r2) as f64
                / (t_total as f64)
                * 100.0
        );
    }

    #[test]
    fn ik_roundtrip_and_bidirectional_transport() {
        let (is, rs, ie, re) = keys();
        let rs_pub = public_of(&rs);

        let mut ini = Initiator::new(is, rs_pub, ie);
        let mut resp = Responder::new(rs, re);

        let msg1 = ini.write_message_1(b"hello from initiator");
        assert_eq!(
            resp.read_message_1(&msg1).as_deref(),
            Some(&b"hello from initiator"[..])
        );

        let (msg2, mut resp_tp) = resp.write_message_2(b"hello from responder").expect("msg2");
        let (mut ini_tp, p2) = ini.read_message_2(&msg2).expect("read msg2");
        assert_eq!(p2, b"hello from responder");

        // initiator -> responder
        let c = ini_tp.send.encrypt_with_ad(b"", b"ping");
        assert_eq!(
            resp_tp.recv.decrypt_with_ad(b"", &c).as_deref(),
            Some(&b"ping"[..])
        );
        // responder -> initiator
        let c2 = resp_tp.send.encrypt_with_ad(b"", b"pong");
        assert_eq!(
            ini_tp.recv.decrypt_with_ad(b"", &c2).as_deref(),
            Some(&b"pong"[..])
        );
    }

    #[test]
    fn transport_recv_at_tolerates_reorder_and_rejects_replay() {
        let (is, rs, ie, re) = keys();
        let rs_pub = public_of(&rs);
        let mut ini = Initiator::new(is, rs_pub, ie);
        let mut resp = Responder::new(rs, re);
        let msg1 = ini.write_message_1(b"");
        resp.read_message_1(&msg1).expect("msg1");
        let (msg2, mut resp_tp) = resp.write_message_2(b"").expect("msg2");
        let (mut ini_tp, _) = ini.read_message_2(&msg2).expect("read msg2");

        // initiator encrypts three packets, recording each packet's counter
        let payloads: [&[u8]; 3] = [b"alpha", b"bravo", b"charlie"];
        let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
        for p in payloads {
            let counter = ini_tp.send_counter();
            let mut buf = vec![0u8; p.len() + 16];
            buf[..p.len()].copy_from_slice(p);
            let framed = ini_tp.send.encrypt_in_place(b"", &mut buf, p.len());
            frames.push((counter, buf[..framed].to_vec()));
        }

        // responder accepts them out of order (2, 0, 1)
        for &i in &[2usize, 0, 1] {
            let (counter, frame) = &frames[i];
            let mut buf = frame.clone();
            let len = buf.len();
            let pt = resp_tp.recv_at(*counter, b"", &mut buf, len);
            assert_eq!(pt, Some(payloads[i].len()), "reordered packet {i} accepted");
            assert_eq!(&buf[..payloads[i].len()], payloads[i]);
        }

        // replaying any already-seen counter is rejected
        let (counter, frame) = &frames[0];
        let mut buf = frame.clone();
        let len = buf.len();
        assert_eq!(
            resp_tp.recv_at(*counter, b"", &mut buf, len),
            None,
            "replay rejected"
        );
    }

    #[test]
    fn tampered_message1_is_rejected() {
        let (is, rs, ie, _re) = keys();
        let rs_pub = public_of(&rs);
        let mut ini = Initiator::new(is, rs_pub, ie);
        let mut resp = Responder::new(rs, [0x44; 32]);
        let mut msg1 = ini.write_message_1(b"payload");
        let last = msg1.len() - 1;
        msg1[last] ^= 0x01;
        assert!(resp.read_message_1(&msg1).is_none());
    }

    #[test]
    fn initiator_targeting_wrong_responder_fails() {
        let (is, rs, ie, re) = keys();
        let wrong_rs_pub = public_of(&[0x99; 32]);
        let mut ini = Initiator::new(is, wrong_rs_pub, ie);
        let mut resp = Responder::new(rs, re);
        let msg1 = ini.write_message_1(b"payload");
        // responder's es/ss DH won't match what the initiator used → AEAD fails.
        assert!(resp.read_message_1(&msg1).is_none());
    }
}
