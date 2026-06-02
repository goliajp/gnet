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
//!
//! Every design choice in this construction (pre-message binding for ML-KEM
//! `ek`, ciphertext-in-clear with `mix_hash`, `mix_key(mlkem_ss)` ordering,
//! unchanged message 2, primitive selection, RNG-free API) is anchored to
//! peer-reviewed work in [`HYBRID.md`](../HYBRID.md) in this crate's root.
//! At the time of writing there is no published cross-implementation test
//! vector for Noise + ML-KEM; the `frozen_hybrid_handshake_kat` test at
//! the bottom of this file (under `#[cfg(test)]`) pins **our** wire stream
//! against accidental drift between releases.

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
        let n = self.sym.encrypt_and_hash_in_place(
            &mut msg[p_off..p_off + payload.len() + TAG_LEN],
            payload.len(),
        );
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
        let s_len = self
            .sym
            .decrypt_and_hash_in_place(&mut s_buf, 32 + TAG_LEN)?;
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

    /// Frozen byte-exact transcript for `Noise_pqIKhybrid_25519MLKEM768_ChaChaPoly_BLAKE2s`.
    ///
    /// There is no published cross-implementation test vector for Noise +
    /// ML-KEM at the time of writing — Noise Framework's PQ extension and the
    /// IETF pquip drafts are still in flight. This test pins **our** wire
    /// stream so any refactor that quietly changes the construction
    /// (mix_hash ordering, mix_key inputs, ML-KEM domain separation, …)
    /// surfaces immediately rather than silently breaking interop with our
    /// own past releases. See `HYBRID.md` for the construction rationale.
    ///
    /// Update the `EXPECTED_*` constants only when the construction is
    /// **intentionally** changed; document the change + bump the protocol
    /// name suffix (e.g. `Noise_pqIKhybrid_…_v2`) in the same commit.
    #[test]
    fn frozen_hybrid_handshake_kat() {
        // Pinned inputs. The byte values are arbitrary but committed so the
        // KAT is bit-reproducible.
        let init_static_priv = [0x01u8; 32];
        let init_ephemeral = [0x02u8; 32];
        let init_encaps_m = [0x03u8; 32];
        let resp_static_priv = [0x10u8; 32];
        let resp_mlkem_d = [0x20u8; 32];
        let resp_mlkem_z = [0x21u8; 32];
        let resp_ephemeral = [0x30u8; 32];
        let init_payload = b"frozen-kat-init-payload" as &[u8];
        let resp_payload = b"frozen-kat-resp-payload" as &[u8];
        let probe = b"frozen-kat-probe-32-byte-payload" as &[u8];

        let (resp_ek, resp_dk) = mlkem::keygen(&resp_mlkem_d, &resp_mlkem_z);
        let resp_static_pub = public_of(&resp_static_priv);

        let mut ini = HybridInitiator::new(
            init_static_priv,
            resp_static_pub,
            &resp_ek,
            init_ephemeral,
            init_encaps_m,
        );
        let mut resp = HybridResponder::new(resp_static_priv, &resp_ek, &resp_dk, resp_ephemeral);

        let m1 = ini.write_message_1(init_payload);
        assert_eq!(
            resp.read_message_1(&m1).as_deref(),
            Some(init_payload),
            "responder reads back the initiator payload"
        );

        let (m2, mut resp_t) = resp
            .write_message_2(resp_payload)
            .expect("responder writes msg2");
        let (mut ini_t, m2_payload) = ini.read_message_2(&m2).expect("initiator reads msg2");
        assert_eq!(m2_payload, resp_payload);

        // Encrypt a fixed probe both directions. Equal ciphertext at counter
        // 0 under ChaCha20-Poly1305 implies the underlying CipherState key
        // matched, so this is a (key-non-exposing) proxy for "transport key
        // didn't change".
        let ini_send_ct = ini_t.send.encrypt_with_ad(b"", probe);
        let resp_send_ct = resp_t.send.encrypt_with_ad(b"", probe);

        // Cross-side sanity: the partner decrypts the probe back to the
        // plaintext, so the test wouldn't pass with a working KAT but a
        // broken bidirectional pair.
        assert_eq!(
            resp_t.recv.decrypt_with_ad(b"", &ini_send_ct).as_deref(),
            Some(probe),
            "responder decrypts the initiator probe"
        );
        assert_eq!(
            ini_t.recv.decrypt_with_ad(b"", &resp_send_ct).as_deref(),
            Some(probe),
            "initiator decrypts the responder probe"
        );

        // Byte-exact wire vectors. Total sizes:
        //   msg1 = e(32) + enc_s(32+16) + mlkem_ct(1088) + enc_payload(23+16) = 1207
        //   msg2 = re(32) + enc_payload(23+16) = 71
        //   each ChaCha20-Poly1305 probe ciphertext = 32 + 16 = 48
        const EXPECTED_M1_HEX: &str = "\
            ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59\
            42e3cefbf97be48f9d088902e3f8fedeae37fea3b9c4da2221731913af11217f\
            8fc547106aee8281c5e181786f74ddd49a04291fe7cd4af7faef9e4d3c7e5026\
            3a066ad1a07c6120446ee02b0093da6663ac7b1f76aa3d3991bfac2f48a8d797\
            2ca627f63359d14d81fecd99248b7e8955f87a0d66ed84cd4cb269be276f0bcc\
            7a53762ed0ec316df4ce8e03a07ad7519d45ebc8a794d7cce86db77a13166ce3\
            ab46260f69fb25ff56c8aadeff9a58d74f4225f5b7f35d81cb3c647ad1e413e9\
            d362d596d96b4843ac830db36eba03d75e983b0c6bbfc74bd7263bbdece2a6b2\
            8c604399e7e6421fccbe649e05732d77816991e91a9f89f116c3aad926694f7d\
            5b2b90ea707411cf8811f8bb8e4a9b285881885e01a43e34b38c7898eb1516cc\
            1a51e82c289f9d2610e361bd796f4b94c9738d4b72c7e320e193a8ec4ea0df56\
            c4c5d92167520717538fc5c760fd90086035d92a5ab7cc2861d24227546b4a21\
            c4e544e4d8212b0a93d1e13a83de0df3504e8f51dcb830c5b1d0840c6ebf0a16\
            f4bb65c0f6c6144462c491b390ffb5d177ee2fdb2a7ef74559706ca34cb8c9e5\
            89c378cf4548c50be35a3768c4e8ce77417a471d828a2be8372fac99e5a918c5\
            fdb85dd679bc25ac2755303c79f039aa43714e66e942159d699b1cfa27ec6d33\
            6fae296df9815ff4ff87c614b79ac7571c1da78b50b546570ec4f284ba754e35\
            f459db4db8e9a87302976bf5fc5b99021fed27a2a5406c5fa3e5ceafcb7521a9\
            70867207922f566a11bfba73502138bae2a925cb895d9be7c8af61c5a4197f8e\
            89e94a3299e23ed4a93cccdad0b30759398285b906b318f1d645013f3833f1b6\
            505b80d1973586decd9b31747dc30281e298a70230b6840d78c0fc9551949f09\
            c4894848bc7bfdfecc54eea10a5fe7da370ad4b0d61a1886448fdab1e2fce42c\
            5430d71db0dad1f1a2aa621d3a1d0375fcd1129183d597724b8c24c2ea838de7\
            c535b1cf35f3eb77ef3bf7cc167952395eb0677c4efb666d29ea2735d31c6d9a\
            b2dd833609bc521258bc270ce49cddf982d0f49ad0a80e2c2b1aca875c8487ef\
            5f81409bd861fd37ed17b8c483cc2f401caf92e79640366f48e726f36b946938\
            c573f806b7fa45279523952756963913ab993087af3e6c3ec59f673a5dc458a7\
            e77cdc14e5e873e63ef90958d0672579267fe0e5ab37375495b2ac0a8e5fe662\
            24122a48e19c7eb43901365e126e146102d8df7b69beebbac0e5b4f0560d1e93\
            5b58cf7e6480ab9adcce22440633ddd6ef5a0a1d6cb006cef9c3a35a09085e78\
            0c25582e51da9baf447a5d11996e64924d479122948cedb4a174c50445358c53\
            41647a7ef6b05038ce8aa96092a7eeb36a0b842a5837094a2c1f95fff42fed81\
            b053dfb5848399504e7d56dc0c4fc46b348963d2e6dd69d08d71932270db178e\
            9c0bd70484454eedfaf1649f3913a4f4fca922ae8516557cc0192dac107e9df6\
            654145b909fd913b4b934b30a6e74dbd20bb710de13ffc0ecb64eec5f9662264\
            19620ca9f3f7a5eb28c3cbb6e9f15670ea5701fef49817e72e364487fee65b45\
            597cd1dc4276e043cbc20f8d878ab3b8b362c9bd57071a12071bc0856dcadf29\
            c68c9c21a7255a8ed64d510d09541be05e410359a3de15";
        const EXPECTED_M2_HEX: &str = "\
            e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f\
            49d7ec4b8f43199f6476ee122130378c30691fa429adcbb30c696b0a2793fe51\
            35259f2d24b7f1";
        const EXPECTED_INI_SEND_CT_HEX: &str = "\
            1e65d3cd3e60ea33ce77b2c6b0cc24e27aab5bfa52ff7002d3df98f86b1fd516\
            39ffa3b9bb3c7ad524bd7bd8ff5a108b";
        const EXPECTED_RESP_SEND_CT_HEX: &str = "\
            95d7518b52f077cbad785b3218e46478d5a686b6cd8d1329ea7d4e22e691ffec\
            074b6b59ce8613cacc663f23f335552e";

        assert_eq!(gnet_hex::encode(&m1), EXPECTED_M1_HEX, "msg1 KAT mismatch");
        assert_eq!(gnet_hex::encode(&m2), EXPECTED_M2_HEX, "msg2 KAT mismatch");
        assert_eq!(
            gnet_hex::encode(&ini_send_ct),
            EXPECTED_INI_SEND_CT_HEX,
            "initiator→responder transport ciphertext KAT mismatch"
        );
        assert_eq!(
            gnet_hex::encode(&resp_send_ct),
            EXPECTED_RESP_SEND_CT_HEX,
            "responder→initiator transport ciphertext KAT mismatch"
        );
    }
}
