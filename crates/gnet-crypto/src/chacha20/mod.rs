//! ChaCha20 stream cipher — RFC 8439.
//!
//! The scalar core is constant-time by construction (only add / xor / rotate
//! on fixed-position words). On aarch64, [`apply_keystream`] processes the
//! bulk four blocks at a time with NEON (private `neon` module); the tail and
//! all other targets use the scalar [`block`] function.

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(target_arch = "x86_64")]
mod sse2;

/// First four state words: the ASCII constant `"expand 32-byte k"` read as
/// little-endian `u32`s (RFC 8439 §2.3).
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The ChaCha quarter-round (RFC 8439 §2.1): mixes four 32-bit words via
/// add / xor / rotate.
#[inline]
pub fn quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(7);
    (a, b, c, d)
}

/// Apply the quarter-round to four indices of the 16-word state in place.
#[inline]
fn quarter_round_state(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let (na, nb, nc, nd) = quarter_round(s[a], s[b], s[c], s[d]);
    s[a] = na;
    s[b] = nb;
    s[c] = nc;
    s[d] = nd;
}

/// Build the initial 16-word state from key, block counter, and nonce
/// (RFC 8439 §2.3).
fn init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&CONSTANTS);
    for (word, chunk) in s[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
    }
    s[12] = counter;
    for (word, chunk) in s[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
    }
    s
}

/// The ChaCha20 block function (RFC 8439 §2.3): 20 rounds, add the original
/// state, serialize little-endian into a 64-byte keystream block.
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let initial = init_state(key, counter, nonce);
    let mut s = initial;
    for _ in 0..10 {
        // column round
        quarter_round_state(&mut s, 0, 4, 8, 12);
        quarter_round_state(&mut s, 1, 5, 9, 13);
        quarter_round_state(&mut s, 2, 6, 10, 14);
        quarter_round_state(&mut s, 3, 7, 11, 15);
        // diagonal round
        quarter_round_state(&mut s, 0, 5, 10, 15);
        quarter_round_state(&mut s, 1, 6, 11, 12);
        quarter_round_state(&mut s, 2, 7, 8, 13);
        quarter_round_state(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&s[i].wrapping_add(initial[i]).to_le_bytes());
    }
    out
}

/// Encrypt or decrypt `data` in place with ChaCha20 (RFC 8439 §2.4),
/// starting from block counter `counter`. XOR-symmetric: the same call
/// decrypts. On aarch64 the bulk is produced four blocks at a time with
/// NEON; the remainder uses the scalar block function.
pub fn apply_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut offset = 0usize;
    let mut block_index = 0u32;

    #[cfg(target_arch = "aarch64")]
    {
        while data.len() - offset >= 256 {
            let ks = neon::keystream4(key, counter.wrapping_add(block_index), nonce);
            xor(&mut data[offset..offset + 256], &ks);
            offset += 256;
            block_index = block_index.wrapping_add(4);
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            while data.len() - offset >= 512 {
                // SAFETY: AVX2 just detected at runtime.
                let ks = unsafe { avx2::keystream8(key, counter.wrapping_add(block_index), nonce) };
                xor(&mut data[offset..offset + 512], &ks);
                offset += 512;
                block_index = block_index.wrapping_add(8);
            }
        }
        while data.len() - offset >= 256 {
            let ks = sse2::keystream4(key, counter.wrapping_add(block_index), nonce);
            xor(&mut data[offset..offset + 256], &ks);
            offset += 256;
            block_index = block_index.wrapping_add(4);
        }
    }

    while offset < data.len() {
        let ks = block(key, counter.wrapping_add(block_index), nonce);
        let end = (offset + 64).min(data.len());
        xor(&mut data[offset..end], &ks[..end - offset]);
        offset = end;
        block_index = block_index.wrapping_add(1);
    }
}

/// XOR keystream `ks` into `dst` (the caller matches the lengths).
fn xor(dst: &mut [u8], ks: &[u8]) {
    for (d, k) in dst.iter_mut().zip(ks) {
        *d ^= *k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.1.1 — single quarter-round test vector.
    #[test]
    fn quarter_round_rfc8439_2_1_1() {
        let out = quarter_round(0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567);
        assert_eq!(out, (0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb));
    }

    /// RFC 8439 §2.3.2 — full block-function keystream vector.
    #[test]
    fn block_rfc8439_2_3_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(block(&key, 1, &nonce), expected);
    }

    /// RFC 8439 §2.4.2 — end-to-end encryption (114 bytes, two blocks).
    #[test]
    fn encrypt_rfc8439_2_4_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        apply_keystream(&key, 1, &nonce, &mut buf);
        let expected: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];
        assert_eq!(buf, expected);
    }

    /// `apply_keystream` (NEON 4-way bulk + scalar tail on aarch64) must equal
    /// the concatenation of scalar `block()` keystreams across 1000 bytes at a
    /// non-zero start counter.
    #[test]
    fn apply_keystream_matches_scalar_reference() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x3c);
        let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);
        let counter = 7u32;

        let mut buf = vec![0u8; 1000];
        apply_keystream(&key, counter, &nonce, &mut buf);

        let mut reference = Vec::with_capacity(1024);
        let mut bi = 0u32;
        while reference.len() < 1000 {
            reference.extend_from_slice(&block(&key, counter.wrapping_add(bi), &nonce));
            bi = bi.wrapping_add(1);
        }
        reference.truncate(1000);
        assert_eq!(buf, reference);
    }
}
