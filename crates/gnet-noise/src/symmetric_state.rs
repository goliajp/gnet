//! Noise `SymmetricState` — chaining key, transcript hash, and the running
//! cipher (Noise Protocol Framework §5.2). HKDF over HMAC-BLAKE2s and the
//! BLAKE2s transcript hash come from `gnet-crypto`.

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
            blake2s::hash_into(&mut h, protocol_name);
        }
        Self {
            ck: h,
            h,
            cs: CipherState::empty(),
        }
    }

    /// `MixHash(data)`: `h = HASH(h ‖ data)`. Streams both pieces through
    /// `blake2s::Hasher` — no intermediate Vec.
    #[inline]
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = blake2s::Hasher::new(HASH_LEN);
        hasher.update(&self.h);
        hasher.update(data);
        let mut out = [0u8; HASH_LEN];
        hasher.finalize_into(&mut out);
        self.h = out;
    }

    /// `MixKey(ikm)`: derive a new chaining key and cipher key via HKDF(2).
    /// Allocation-free: the OKM lands in a fixed-size stack buffer.
    #[inline]
    pub fn mix_key(&mut self, ikm: &[u8]) {
        let tk = hkdf::extract(&self.ck, ikm);
        let mut okm = [0u8; 2 * HASH_LEN];
        hkdf::expand_into(&tk, b"", &mut okm);
        self.ck.copy_from_slice(&okm[..HASH_LEN]);
        let mut k = [0u8; HASH_LEN];
        k.copy_from_slice(&okm[HASH_LEN..2 * HASH_LEN]);
        self.cs = CipherState::new(k);
    }

    /// `EncryptAndHash(plaintext)`: AEAD-encrypt bound to `h`, then mix the
    /// ciphertext into the transcript. Allocating wrapper retained for the
    /// pre-existing API surface — the handshake hot path uses
    /// [`encrypt_and_hash_in_place`](Self::encrypt_and_hash_in_place).
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let c = self.cs.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&c);
        c
    }

    /// In-place form of [`encrypt_and_hash`](Self::encrypt_and_hash):
    /// `buf[..plain_len]` is the plaintext; on return `buf[..plain_len + 16]`
    /// is the ciphertext+tag, and the ciphertext has been mixed into the
    /// transcript. Caller must size `buf` for at least `plain_len + 16`.
    /// Returns the framed length (`plain_len + 16` when keyed, `plain_len`
    /// pass-through otherwise).
    #[inline]
    pub fn encrypt_and_hash_in_place(&mut self, buf: &mut [u8], plain_len: usize) -> usize {
        // CipherState::encrypt_in_place takes &[u8] AAD; self.h is unchanged
        // until we explicitly mix_hash, so we can pass &self.h directly.
        let ct_len = self.cs.encrypt_in_place(&self.h, buf, plain_len);
        self.mix_hash(&buf[..ct_len]);
        ct_len
    }

    /// `DecryptAndHash(data)`: AEAD-decrypt bound to `h`, then mix the
    /// ciphertext into the transcript. `None` on authentication failure.
    pub fn decrypt_and_hash(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let pt = self.cs.decrypt_with_ad(&self.h, data)?;
        self.mix_hash(data);
        Some(pt)
    }

    /// In-place form of [`decrypt_and_hash`](Self::decrypt_and_hash):
    /// `buf[..len]` is the ciphertext+tag; on success the plaintext occupies
    /// `buf[..len - 16]` and that length is returned. The mix-hash operates
    /// on the ciphertext, so we snapshot `h` as the AAD for decryption and
    /// mix the ciphertext into `self.h` BEFORE the in-place decrypt scrambles
    /// the bytes — the snapshotted AAD preserves the pre-mix value the
    /// receiver needs to match the sender's encrypt-time AAD.
    #[inline]
    pub fn decrypt_and_hash_in_place(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        let ad = self.h;
        self.mix_hash(&buf[..len]);
        self.cs.decrypt_in_place(&ad, buf, len)
    }

    /// `Split()`: derive the two transport cipher states (Noise §5.2). The
    /// first is for initiator→responder, the second for responder→initiator.
    pub fn split(&self) -> (CipherState, CipherState) {
        let tk = hkdf::extract(&self.ck, b"");
        let mut okm = [0u8; 2 * HASH_LEN];
        hkdf::expand_into(&tk, b"", &mut okm);
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

    /// In-place encrypt/decrypt must agree with the owned-buffer wrappers
    /// AND must leave the transcript in the same state on both sides.
    #[test]
    fn in_place_roundtrip_matches_owned() {
        let pt = b"some Noise payload that spans more than 16 bytes for sure";
        // Reference (owned) path
        let mut a = SymmetricState::new(PROTO);
        let mut b = SymmetricState::new(PROTO);
        a.mix_key(&[3u8; 32]);
        b.mix_key(&[3u8; 32]);
        let c = a.encrypt_and_hash(pt);
        let p = b.decrypt_and_hash(&c).expect("owned decrypt");
        assert_eq!(p, pt);
        let ref_h = a.handshake_hash();

        // In-place path
        let mut a2 = SymmetricState::new(PROTO);
        let mut b2 = SymmetricState::new(PROTO);
        a2.mix_key(&[3u8; 32]);
        b2.mix_key(&[3u8; 32]);
        let mut buf = vec![0u8; pt.len() + 16];
        buf[..pt.len()].copy_from_slice(pt);
        let n = a2.encrypt_and_hash_in_place(&mut buf, pt.len());
        assert_eq!(n, pt.len() + 16);
        assert_eq!(&buf[..n], &c[..]);
        let pt_len = b2
            .decrypt_and_hash_in_place(&mut buf, n)
            .expect("in-place decrypt");
        assert_eq!(&buf[..pt_len], pt);
        assert_eq!(a2.handshake_hash(), ref_h);
        assert_eq!(b2.handshake_hash(), ref_h);
    }
}
