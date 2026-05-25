//! BLAKE2s cryptographic hash — RFC 7693.
//!
//! 32-bit words, 8-word chaining state, 64-byte blocks, 10 rounds of the
//! `G` mixing function under the SIGMA message schedule. Supports a
//! configurable digest length (1..=32) and an optional key (1..=32 bytes,
//! whose padded value forms the first compressed block). 0-dependency.

/// Initialization vector (identical to the SHA-256 IV).
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Message-word permutation schedule (10 rounds for BLAKE2s).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The `G` mixing function (BLAKE2s rotations 16/12/8/7).
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// Compress one 64-byte block into the state. `t` is the byte counter
/// including this block; `last` marks the final block.
fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] ^= 0xffff_ffff;
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (i, hi) in h.iter_mut().enumerate() {
        *hi ^= v[i] ^ v[i + 8];
    }
}

/// Serialize the first `outlen` bytes of the state (little-endian).
fn output(h: &[u32; 8], outlen: usize) -> Vec<u8> {
    let mut bytes = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    bytes[..outlen].to_vec()
}

/// Core BLAKE2s: hash `msg` with optional `key`, producing `outlen` bytes.
///
/// # Panics
/// If `outlen` is not in `1..=32` or `key.len() > 32`.
pub fn blake2s(outlen: usize, key: &[u8], msg: &[u8]) -> Vec<u8> {
    assert!((1..=32).contains(&outlen), "outlen must be 1..=32");
    assert!(key.len() <= 32, "key must be <= 32 bytes");

    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ (outlen as u32);
    let mut t: u64 = 0;

    if !key.is_empty() {
        let mut kb = [0u8; 64];
        kb[..key.len()].copy_from_slice(key);
        if msg.is_empty() {
            compress(&mut h, &kb, 64, true);
            return output(&h, outlen);
        }
        t = 64;
        compress(&mut h, &kb, t, false);
    } else if msg.is_empty() {
        compress(&mut h, &[0u8; 64], 0, true);
        return output(&h, outlen);
    }

    // msg is non-empty here
    let n = msg.len();
    let full_end = if n.is_multiple_of(64) {
        n - 64
    } else {
        n - (n % 64)
    };
    let mut off = 0;
    while off < full_end {
        let block: [u8; 64] = msg[off..off + 64].try_into().unwrap();
        t += 64;
        compress(&mut h, &block, t, false);
        off += 64;
    }
    let rem = &msg[off..];
    let mut block = [0u8; 64];
    block[..rem.len()].copy_from_slice(rem);
    t += rem.len() as u64;
    compress(&mut h, &block, t, true);
    output(&h, outlen)
}

/// Unkeyed BLAKE2s hash producing `out_len` bytes.
pub fn hash(out_len: usize, msg: &[u8]) -> Vec<u8> {
    blake2s(out_len, &[], msg)
}

/// Keyed BLAKE2s (MAC mode) producing `out_len` bytes.
pub fn keyed(out_len: usize, key: &[u8], msg: &[u8]) -> Vec<u8> {
    blake2s(out_len, key, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        (0..s.len() / 2)
            .map(|i| {
                let hi = char::from(b[2 * i]).to_digit(16).unwrap() as u8;
                let lo = char::from(b[2 * i + 1]).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// RFC 7693 §B — BLAKE2s-256 of "abc".
    #[test]
    fn blake2s_abc() {
        assert_eq!(
            hash(32, b"abc"),
            hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
    }

    /// BLAKE2s-256 of the empty input.
    #[test]
    fn blake2s_empty() {
        assert_eq!(
            hash(32, b""),
            hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    /// Official BLAKE2s keyed KAT #0: key = 00..1f, empty message.
    #[test]
    fn blake2s_keyed_empty() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            keyed(32, &key, b""),
            hex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
        );
    }

    /// A multi-block input (200 bytes) exercises the block loop + counter.
    #[test]
    fn blake2s_multiblock_is_stable() {
        let msg = vec![0xa5u8; 200];
        let d = hash(32, &msg);
        assert_eq!(d.len(), 32);
        // recomputation is deterministic
        assert_eq!(d, hash(32, &msg));
    }
}
