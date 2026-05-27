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

/// Build the zero-padded HMAC key block `K0` from `key`. If `key.len() > BLOCK`,
/// the key is pre-hashed; otherwise it is zero-padded.
#[inline]
fn build_k0(key: &[u8]) -> [u8; BLOCK] {
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut prehashed = [0u8; HASH_LEN];
        blake2s::hash_into(&mut prehashed, key);
        k0[..HASH_LEN].copy_from_slice(&prehashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    k0
}

/// HMAC-BLAKE2s (RFC 2104) over the unkeyed BLAKE2s-256 hash. Allocation-
/// free: streams the inner and outer hashes through [`blake2s::Hasher`]
/// without materializing any intermediate buffer.
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; HASH_LEN] {
    let k0 = build_k0(key);
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    hmac_with_pads(&ipad, &opad, msg)
}

/// HMAC core given pre-computed (k0 ^ ipad) and (k0 ^ opad). Streams both
/// hashes through `blake2s::Hasher` without allocation.
#[inline]
fn hmac_with_pads(ipad: &[u8; BLOCK], opad: &[u8; BLOCK], msg: &[u8]) -> [u8; HASH_LEN] {
    let mut inner = blake2s::Hasher::new(HASH_LEN);
    inner.update(ipad);
    inner.update(msg);
    let mut inner_hash = [0u8; HASH_LEN];
    inner.finalize_into(&mut inner_hash);

    let mut outer = blake2s::Hasher::new(HASH_LEN);
    outer.update(opad);
    outer.update(&inner_hash);
    let mut tag = [0u8; HASH_LEN];
    outer.finalize_into(&mut tag);
    tag
}

/// Streaming HMAC variant for HKDF-Expand: the inner update takes
/// `(T(i-1) || info || counter)` as three separate slices to avoid building
/// an intermediate concat buffer.
#[inline]
fn hmac_three_with_pads(
    ipad: &[u8; BLOCK],
    opad: &[u8; BLOCK],
    a: &[u8],
    b: &[u8],
    c: &[u8],
) -> [u8; HASH_LEN] {
    let mut inner = blake2s::Hasher::new(HASH_LEN);
    inner.update(ipad);
    inner.update(a);
    inner.update(b);
    inner.update(c);
    let mut inner_hash = [0u8; HASH_LEN];
    inner.finalize_into(&mut inner_hash);

    let mut outer = blake2s::Hasher::new(HASH_LEN);
    outer.update(opad);
    outer.update(&inner_hash);
    let mut tag = [0u8; HASH_LEN];
    outer.finalize_into(&mut tag);
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

/// HKDF-Expand into a caller-provided buffer (RFC 5869 §2.3): derive
/// `out.len()` bytes of output keying material from `prk` and context
/// `info`. Allocation-free. The HMAC key `prk` is constant across the
/// expand loop, so `(K0 ^ ipad)` and `(K0 ^ opad)` are computed once and
/// reused for each block — half the work of recomputing per iteration.
///
/// # Panics
/// If `out.len() > 255 * 32`.
pub fn expand_into(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * HASH_LEN, "HKDF-Expand length too large");
    // Constant-across-loop HMAC pads.
    let k0 = build_k0(prk);
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    // T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i).
    let mut t_prev = [0u8; HASH_LEN];
    let mut t_prev_len = 0usize;
    let mut written = 0usize;
    let mut counter: usize = 1;
    while written < out.len() {
        assert!(counter <= 255, "HKDF counter exceeds 255");
        let counter_byte = [counter as u8];
        t_prev = hmac_three_with_pads(
            &ipad,
            &opad,
            &t_prev[..t_prev_len],
            info,
            &counter_byte,
        );
        t_prev_len = HASH_LEN;
        let chunk = (out.len() - written).min(HASH_LEN);
        out[written..written + chunk].copy_from_slice(&t_prev[..chunk]);
        written += chunk;
        counter += 1;
    }
}

/// HKDF-Expand (RFC 5869 §2.3): derive `len` bytes of output keying
/// material from `prk` and context `info`.
///
/// # Panics
/// If `len > 255 * 32`.
pub fn expand(prk: &[u8; HASH_LEN], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    expand_into(prk, info, &mut out);
    out
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

    /// `expand_into` must equal `expand` for the same input.
    #[test]
    fn expand_into_matches_expand() {
        let prk = extract(b"some-salt", b"some-ikm");
        for len in [1usize, 32, 33, 64, 100] {
            let v = expand(&prk, b"ctx", len);
            let mut buf = vec![0u8; len];
            expand_into(&prk, b"ctx", &mut buf);
            assert_eq!(buf, v, "len {len}");
        }
    }
}
