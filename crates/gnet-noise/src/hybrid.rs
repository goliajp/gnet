//! Post-quantum hybrid handshake: `Noise_IK` (X25519) augmented with an
//! ML-KEM-768 encapsulation, so the transport keys depend on **both** the
//! classical Diffie-Hellman and the post-quantum KEM — secure if either
//! primitive holds.
//!
//! The responder's ML-KEM encapsulation key is a pre-message (known to the
//! initiator in advance, like the IK static, and bound into the transcript).
//! In message 1 the initiator encapsulates to it; the ciphertext travels in
//! the clear (a KEM ciphertext needs no confidentiality) but is mixed into the
//! transcript hash, and the resulting shared secret is folded into the chaining
//! key with `MixKey` before the payload. Message 2 is unchanged `IK` (`e, ee,
//! se`). Ephemerals and the encapsulation message are caller-injected, keeping
//! this crate RNG-free.

use crate::handshake::Transport;
use crate::symmetric_state::SymmetricState;
use gnet_crypto::{mlkem, x25519};

const PROTOCOL_NAME: &[u8] = b"Noise_pqIKhybrid_25519MLKEM768_ChaChaPoly_BLAKE2s";
const TAG_LEN: usize = 16;

#[inline]
fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519::x25519(secret, public)
}

/// Test-only single-key derivation helper. Production paths use
/// [`x25519::x25519_base_pair`] for the static + ephemeral pair.
#[cfg(test)]
#[inline]
fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    x25519::x25519_base(secret)
}

/// The hybrid handshake initiator. Knows the responder's X25519 static key and
/// ML-KEM encapsulation key.
pub struct HybridInitiator {
    sym: SymmetricState,
    s_priv: [u8; 32],
    s_pub: [u8; 32],
    e_priv: [u8; 32],
    e_pub: [u8; 32],
    rs: [u8; 32],
    mlkem_ek: Vec<u8>,
    encaps_m: [u8; 32],
}

impl HybridInitiator {
    /// Create an initiator from its X25519 static key, the responder's X25519
    /// static public key and ML-KEM encapsulation key, an injected ephemeral,
    /// and the injected ML-KEM encapsulation randomness.
    pub fn new(
        static_priv: [u8; 32],
        responder_static_pub: [u8; 32],
        responder_mlkem_ek: &[u8],
        ephemeral_priv: [u8; 32],
        encaps_m: [u8; 32],
    ) -> Self {
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(&[]); // prologue
        sym.mix_hash(&responder_static_pub); // pre-message: responder X25519 static
        sym.mix_hash(responder_mlkem_ek); // pre-message: responder ML-KEM ek
        // One shared finvert across both X25519 derivations.
        let [s_pub, e_pub] = x25519::x25519_base_pair([&static_priv, &ephemeral_priv]);
        Self {
            sym,
            s_pub,
            e_pub,
            s_priv: static_priv,
            e_priv: ephemeral_priv,
            rs: responder_static_pub,
            mlkem_ek: responder_mlkem_ek.to_vec(),
            encaps_m,
        }
    }

    /// Write message 1 (`e, es, s, ss, mlkem_ct` + payload). One allocation:
    /// the returned `Vec` is sized exactly for the framed wire bytes (plus the
    /// transient `Vec` from `mlkem::encaps`, which is constrained by the
    /// existing mlkem API).
    pub fn write_message_1(&mut self, payload: &[u8]) -> Vec<u8> {
        // Layout: e(32) || enc_s(32+16) || mlkem_ct(CT_LEN) || enc_payload(payload+16)
        let total = 32 + (32 + TAG_LEN) + mlkem::CT_LEN + (payload.len() + TAG_LEN);
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

        // ML-KEM encapsulation: the ciphertext is in the clear but contributes
        // to the transcript; the shared secret folds into the chaining key.
        let ct_off = s_off + 32 + TAG_LEN;
        let (mlkem_ss, ct) = mlkem::encaps(&self.mlkem_ek, &self.encaps_m);
        debug_assert_eq!(ct.len(), mlkem::CT_LEN);
        msg[ct_off..ct_off + mlkem::CT_LEN].copy_from_slice(&ct);
        self.sym.mix_hash(&msg[ct_off..ct_off + mlkem::CT_LEN]);
        self.sym.mix_key(&mlkem_ss);

        // payload (encrypted)
        let p_off = ct_off + mlkem::CT_LEN;
        msg[p_off..p_off + payload.len()].copy_from_slice(payload);
        let n = self
            .sym
            .encrypt_and_hash_in_place(&mut msg[p_off..p_off + payload.len() + TAG_LEN], payload.len());
        debug_assert_eq!(n, payload.len() + TAG_LEN);

        msg
    }

    /// Read message 2 (`e, ee, se` + payload), yielding the transport pair.
    /// One allocation: the returned payload `Vec`.
    pub fn read_message_2(mut self, msg: &[u8]) -> Option<(Transport, Vec<u8>)> {
        if msg.len() < 32 + TAG_LEN {
            return None;
        }
        let re_pub: [u8; 32] = msg[..32].try_into().ok()?;
        self.sym.mix_hash(&re_pub);
        self.sym.mix_key(&dh(&self.e_priv, &re_pub)); // ee
        self.sym.mix_key(&dh(&self.s_priv, &re_pub)); // se

        let ct_len = msg.len() - 32;
        let mut payload = vec![0u8; ct_len];
        payload.copy_from_slice(&msg[32..]);
        let pt_len = self.sym.decrypt_and_hash_in_place(&mut payload, ct_len)?;
        payload.truncate(pt_len);

        let (c1, c2) = self.sym.split();
        Some((Transport::new(c1, c2), payload))
    }
}

/// The hybrid handshake responder. Holds its X25519 static key and its ML-KEM
/// key pair.
pub struct HybridResponder {
    sym: SymmetricState,
    s_priv: [u8; 32],
    mlkem_dk: Vec<u8>,
    e_priv: [u8; 32],
    e_pub: [u8; 32],
    initiator_ephemeral: Option<[u8; 32]>,
    initiator_static: Option<[u8; 32]>,
}

impl HybridResponder {
    /// Create a responder from its X25519 static key, its ML-KEM key pair, and
    /// an injected ephemeral.
    pub fn new(
        static_priv: [u8; 32],
        mlkem_ek: &[u8],
        mlkem_dk: &[u8],
        ephemeral_priv: [u8; 32],
    ) -> Self {
        // One shared finvert across both X25519 derivations.
        let [s_pub, e_pub] = x25519::x25519_base_pair([&static_priv, &ephemeral_priv]);
        let mut sym = SymmetricState::new(PROTOCOL_NAME);
        sym.mix_hash(&[]); // prologue
        sym.mix_hash(&s_pub); // pre-message: our X25519 static
        sym.mix_hash(mlkem_ek); // pre-message: our ML-KEM ek
        Self {
            s_priv: static_priv,
            mlkem_dk: mlkem_dk.to_vec(),
            e_pub,
            e_priv: ephemeral_priv,
            sym,
            initiator_ephemeral: None,
            initiator_static: None,
        }
    }

    /// The initiator's X25519 static public key, learned during
    /// [`read_message_1`](Self::read_message_1). A multi-peer node uses it to
    /// match the handshake to a configured peer.
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.initiator_static
    }

    /// Read message 1, decapsulating the ML-KEM ciphertext and learning the
    /// initiator's static key. Returns the initiator's payload. One allocation:
    /// the returned payload `Vec`.
    pub fn read_message_1(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        // e(32) + enc static(48) + mlkem_ct + payload tag(16)
        if msg.len() < 32 + (32 + TAG_LEN) + mlkem::CT_LEN + TAG_LEN {
            return None;
        }
        let ie_pub: [u8; 32] = msg[..32].try_into().ok()?;
        self.initiator_ephemeral = Some(ie_pub);
        self.sym.mix_hash(&ie_pub);
        self.sym.mix_key(&dh(&self.s_priv, &ie_pub)); // es

        // s (decrypt into a 48-byte stack buffer)
        let mut s_buf = [0u8; 32 + TAG_LEN];
        s_buf.copy_from_slice(&msg[32..32 + 32 + TAG_LEN]);
        let s_len = self.sym.decrypt_and_hash_in_place(&mut s_buf, 32 + TAG_LEN)?;
        if s_len != 32 {
            return None;
        }
        let is_pub: [u8; 32] = s_buf[..32].try_into().ok()?;
        self.initiator_static = Some(is_pub);
        self.sym.mix_key(&dh(&self.s_priv, &is_pub)); // ss

        // ML-KEM ciphertext (in the clear, but mixed into the transcript and
        // its decapsulated shared secret folded into the chaining key)
        let ct_off = 32 + 32 + TAG_LEN;
        let ct = &msg[ct_off..ct_off + mlkem::CT_LEN];
        self.sym.mix_hash(ct);
        let mlkem_ss = mlkem::decaps(&self.mlkem_dk, ct);
        self.sym.mix_key(&mlkem_ss);

        // payload (decrypt into a Vec sized to the ciphertext)
        let p_off = ct_off + mlkem::CT_LEN;
        let p_ct_len = msg.len() - p_off;
        let mut payload = vec![0u8; p_ct_len];
        payload.copy_from_slice(&msg[p_off..]);
        let pt_len = self.sym.decrypt_and_hash_in_place(&mut payload, p_ct_len)?;
        payload.truncate(pt_len);
        Some(payload)
    }

    /// Write message 2 (`e, ee, se` + payload), yielding the transport pair.
    /// One allocation: the returned `Vec`.
    pub fn write_message_2(mut self, payload: &[u8]) -> Option<(Vec<u8>, Transport)> {
        let ie = self.initiator_ephemeral?;
        let is = self.initiator_static?;
        let total = 32 + payload.len() + TAG_LEN;
        let mut msg = vec![0u8; total];

        self.sym.mix_hash(&self.e_pub);
        msg[0..32].copy_from_slice(&self.e_pub);
        self.sym.mix_key(&dh(&self.e_priv, &ie)); // ee
        self.sym.mix_key(&dh(&self.e_priv, &is)); // se

        msg[32..32 + payload.len()].copy_from_slice(payload);
        let n = self
            .sym
            .encrypt_and_hash_in_place(&mut msg[32..32 + payload.len() + TAG_LEN], payload.len());
        debug_assert_eq!(n, payload.len() + TAG_LEN);

        let (c1, c2) = self.sym.split();
        Some((msg, Transport::new(c2, c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mlkem_keypair() -> (Vec<u8>, Vec<u8>) {
        mlkem::keygen(&[5u8; 32], &[6u8; 32])
    }

    #[test]
    fn hybrid_roundtrip_and_bidirectional_transport() {
        let (ek, dk) = mlkem_keypair();
        let i_s = [0x11u8; 32];
        let r_s = [0x22u8; 32];
        let r_s_pub = public_of(&r_s);

        let mut ini = HybridInitiator::new(i_s, r_s_pub, &ek, [0x33; 32], [0x44; 32]);
        let mut resp = HybridResponder::new(r_s, &ek, &dk, [0x55; 32]);

        let m1 = ini.write_message_1(b"hello pq");
        assert_eq!(resp.read_message_1(&m1).as_deref(), Some(&b"hello pq"[..]));

        let (m2, mut rtp) = resp.write_message_2(b"pong pq").expect("msg2");
        let (mut itp, p2) = ini.read_message_2(&m2).expect("read msg2");
        assert_eq!(p2, b"pong pq");

        let c = itp.send.encrypt_with_ad(b"", b"ping");
        assert_eq!(
            rtp.recv.decrypt_with_ad(b"", &c).as_deref(),
            Some(&b"ping"[..])
        );
        let c2 = rtp.send.encrypt_with_ad(b"", b"pong");
        assert_eq!(
            itp.recv.decrypt_with_ad(b"", &c2).as_deref(),
            Some(&b"pong"[..])
        );
    }

    #[test]
    fn wrong_mlkem_key_breaks_handshake() {
        let (ek, _dk) = mlkem_keypair();
        let (_ek2, wrong_dk) = mlkem::keygen(&[9u8; 32], &[8u8; 32]);
        let r_s = [0x22u8; 32];
        let r_s_pub = public_of(&r_s);

        let mut ini = HybridInitiator::new([0x11; 32], r_s_pub, &ek, [0x33; 32], [0x44; 32]);
        // responder holds the wrong ML-KEM secret key → decaps diverges →
        // the chaining keys differ → message 1 payload fails to authenticate.
        let mut resp = HybridResponder::new(r_s, &ek, &wrong_dk, [0x55; 32]);
        let m1 = ini.write_message_1(b"hello pq");
        assert!(resp.read_message_1(&m1).is_none());
    }

    #[test]
    fn tampered_mlkem_ct_is_rejected() {
        let (ek, dk) = mlkem_keypair();
        let r_s = [0x22u8; 32];
        let r_s_pub = public_of(&r_s);
        let mut ini = HybridInitiator::new([0x11; 32], r_s_pub, &ek, [0x33; 32], [0x44; 32]);
        let mut resp = HybridResponder::new(r_s, &ek, &dk, [0x55; 32]);
        let mut m1 = ini.write_message_1(b"hello pq");
        // flip a byte in the ML-KEM ciphertext region (after e + enc-static).
        m1[32 + 48 + 10] ^= 0x01;
        assert!(resp.read_message_1(&m1).is_none());
    }
}
