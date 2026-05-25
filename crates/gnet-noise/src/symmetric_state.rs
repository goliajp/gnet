//! Noise `SymmetricState` — chaining key, transcript hash, and the running
//! cipher (Noise Protocol Framework §5.2). HKDF over HMAC-BLAKE2s and the
//! BLAKE2s transcript hash come from `mesh-crypto`.

use crate::cipher_state::CipherState;
use gnet_crypto::{blake2s, hkdf};

const HASH_LEN: usize = 32;

/// Noise symmetric state: `ck` (chaining key), `h` (transcript hash) and
/// the current `CipherState`.
pub struct SymmetricState {
    ck: [u8; HASH_LEN],
    h: [u8; HASH_LEN],
    cs: CipherState,
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)` (Noise §5.2). Names longer than
    /// the hash length are hashed; shorter ones are zero-padded.
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut h = [0u8; HASH_LEN];
        if protocol_name.len() <= HASH_LEN {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            h.copy_from_slice(&blake2s::hash(HASH_LEN, protocol_name));
        }
        Self {
            ck: h,
            h,
            cs: CipherState::empty(),
        }
    }

    /// `MixHash(data)`: `h = HASH(h ‖ data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut input = Vec::with_capacity(HASH_LEN + data.len());
        input.extend_from_slice(&self.h);
        input.extend_from_slice(data);
        self.h.copy_from_slice(&blake2s::hash(HASH_LEN, &input));
    }

    /// `MixKey(ikm)`: derive a new chaining key and cipher key via HKDF(2).
    pub fn mix_key(&mut self, ikm: &[u8]) {
        let tk = hkdf::extract(&self.ck, ikm);
        let okm = hkdf::expand(&tk, b"", 2 * HASH_LEN);
        self.ck.copy_from_slice(&okm[..HASH_LEN]);
        let mut k = [0u8; HASH_LEN];
        k.copy_from_slice(&okm[HASH_LEN..2 * HASH_LEN]);
        self.cs = CipherState::new(k);
    }

    /// `EncryptAndHash(plaintext)`: AEAD-encrypt bound to `h`, then mix the
    /// ciphertext into the transcript.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let c = self.cs.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&c);
        c
    }

    /// `DecryptAndHash(data)`: AEAD-decrypt bound to `h`, then mix the
    /// ciphertext into the transcript. `None` on authentication failure.
    pub fn decrypt_and_hash(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let pt = self.cs.decrypt_with_ad(&self.h, data)?;
        self.mix_hash(data);
        Some(pt)
    }

    /// `Split()`: derive the two transport cipher states (Noise §5.2). The
    /// first is for initiator→responder, the second for responder→initiator.
    pub fn split(&self) -> (CipherState, CipherState) {
        let tk = hkdf::extract(&self.ck, b"");
        let okm = hkdf::expand(&tk, b"", 2 * HASH_LEN);
        let mut k1 = [0u8; HASH_LEN];
        let mut k2 = [0u8; HASH_LEN];
        k1.copy_from_slice(&okm[..HASH_LEN]);
        k2.copy_from_slice(&okm[HASH_LEN..2 * HASH_LEN]);
        (CipherState::new(k1), CipherState::new(k2))
    }

    /// The current transcript hash (channel binding value).
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTO: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

    #[test]
    fn mirror_encrypt_decrypt_keeps_transcripts_in_sync() {
        let mut a = SymmetricState::new(PROTO);
        let mut b = SymmetricState::new(PROTO);
        a.mix_key(&[1u8; 32]);
        b.mix_key(&[1u8; 32]);
        let c = a.encrypt_and_hash(b"secret");
        assert_eq!(b.decrypt_and_hash(&c).as_deref(), Some(&b"secret"[..]));
        assert_eq!(a.handshake_hash(), b.handshake_hash());
    }

    #[test]
    fn split_yields_matching_transport_keys() {
        let mut a = SymmetricState::new(PROTO);
        let mut b = SymmetricState::new(PROTO);
        a.mix_key(&[2u8; 32]);
        b.mix_key(&[2u8; 32]);
        let (mut a1, _) = a.split();
        let (mut b1, _) = b.split();
        let c = a1.encrypt_with_ad(b"", b"x");
        assert_eq!(b1.decrypt_with_ad(b"", &c).as_deref(), Some(&b"x"[..]));
    }
}
