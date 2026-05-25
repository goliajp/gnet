//! HKDF key derivation (RFC 5869) instantiated with HMAC-BLAKE2s.
//!
//! BLAKE2s-256 is the underlying hash (32-byte output, 64-byte block). No
//! standard RFC 5869 test vector exists for the BLAKE2s instantiation
//! (the RFC uses SHA-2), so correctness here rests on the KAT-verified
//! [`blake2s`](crate::blake2s) plus a structural HMAC test and HKDF
//! property tests.

use crate::blake2s;

const HASH_LEN: usize = 32;
const BLOCK: usize = 64;

/// HMAC-BLAKE2s (RFC 2104) over the unkeyed BLAKE2s-256 hash.
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; HASH_LEN] {
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        k0[..HASH_LEN].copy_from_slice(&blake2s::hash(HASH_LEN, key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k0.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = blake2s::hash(HASH_LEN, &inner);

    let mut outer = Vec::with_capacity(BLOCK + HASH_LEN);
    outer.extend(k0.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);

    let mut tag = [0u8; HASH_LEN];
    tag.copy_from_slice(&blake2s::hash(HASH_LEN, &outer));
    tag
}

/// HKDF-Extract (RFC 5869 §2.2): `PRK = HMAC(salt, ikm)`. An empty salt is
/// treated as `HashLen` zero bytes.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    if salt.is_empty() {
        hmac(&[0u8; HASH_LEN], ikm)
    } else {
        hmac(salt, ikm)
    }
}

/// HKDF-Expand (RFC 5869 §2.3): derive `len` bytes of output keying
/// material from `prk` and context `info`.
///
/// # Panics
/// If `len > 255 * 32`.
pub fn expand(prk: &[u8; HASH_LEN], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * HASH_LEN, "HKDF-Expand length too large");
    let mut okm = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: usize = 1;
    while okm.len() < len {
        let mut input = Vec::with_capacity(prev.len() + info.len() + 1);
        input.extend_from_slice(&prev);
        input.extend_from_slice(info);
        input.push(counter as u8);
        prev = hmac(prk, &input).to_vec();
        okm.extend_from_slice(&prev);
        counter += 1;
    }
    okm.truncate(len);
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC must equal the textbook construction `H(opad ‖ H(ipad ‖ msg))`.
    #[test]
    fn hmac_matches_textbook_definition() {
        let key = b"the-derivation-key";
        let msg = b"context and material";
        let mut k0 = [0u8; BLOCK];
        k0[..key.len()].copy_from_slice(key);
        let mut inner: Vec<u8> = k0.iter().map(|b| b ^ 0x36).collect();
        inner.extend_from_slice(msg);
        let ih = blake2s::hash(HASH_LEN, &inner);
        let mut outer: Vec<u8> = k0.iter().map(|b| b ^ 0x5c).collect();
        outer.extend_from_slice(&ih);
        assert_eq!(hmac(key, msg).to_vec(), blake2s::hash(HASH_LEN, &outer));
    }

    /// A key longer than the block size is pre-hashed.
    #[test]
    fn hmac_long_key_is_prehashed() {
        let long = vec![0x5au8; 100];
        let prehashed = blake2s::hash(HASH_LEN, &long);
        assert_eq!(hmac(&long, b"x"), hmac(&prehashed, b"x"));
    }

    /// Expand produces exactly the requested length, across multiple blocks.
    #[test]
    fn expand_lengths() {
        let prk = extract(b"salt", b"ikm");
        for len in [0usize, 1, 31, 32, 33, 64, 100, 255 * 32] {
            assert_eq!(expand(&prk, b"info", len).len(), len);
        }
    }

    /// Expand is deterministic and context-sensitive.
    #[test]
    fn expand_deterministic_and_info_sensitive() {
        let prk = extract(b"salt", b"ikm");
        assert_eq!(expand(&prk, b"info-a", 64), expand(&prk, b"info-a", 64));
        assert_ne!(expand(&prk, b"info-a", 64), expand(&prk, b"info-b", 64));
    }

    /// A prefix of a longer expansion equals the shorter expansion (the
    /// HKDF streaming property).
    #[test]
    fn expand_is_a_prefix_stream() {
        let prk = extract(b"", b"input-key-material");
        let long = expand(&prk, b"info", 80);
        let short = expand(&prk, b"info", 40);
        assert_eq!(&long[..40], &short[..]);
    }
}
