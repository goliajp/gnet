//! ML-KEM (FIPS 203) coefficient serialization: the `d`-bit `ByteEncode` /
//! `ByteDecode` packing (Algorithms 5/6) and the lossy `Compress` /
//! `Decompress` maps (Section 4.2.1). Bit-packing is done LSB-first, one bit at
//! a time — clear over fast; the per-byte work is off the per-packet path.

use super::ntt::Q;

/// Reduce a (possibly negative) coefficient to the canonical range `[0, q)`.
pub fn freeze(x: i16) -> u16 {
    x.rem_euclid(Q) as u16
}

/// `Compress_d(x)` = round(2^d / q · x) mod 2^d, for `x` in `[0, q)`.
pub fn compress(d: u32, x: u16) -> u16 {
    let num = ((x as u32) << d) + (Q as u32 / 2);
    ((num / Q as u32) & ((1 << d) - 1)) as u16
}

/// `Decompress_d(y)` = round(q / 2^d · y), for `y` in `[0, 2^d)`.
pub fn decompress(d: u32, y: u16) -> u16 {
    (((y as u32) * Q as u32 + (1 << (d - 1))) >> d) as u16
}

/// `ByteEncode_d`: pack 256 `d`-bit values (LSB-first) into `out` (`32·d`
/// bytes). Inputs must already be in `[0, 2^d)`.
///
/// Fast paths exist for the four `d` values ML-KEM-768 actually uses
/// (12, 10, 4, 1). Each packs `lcm(d, 8) / d` coefficients into
/// `lcm(d, 8) / 8` whole bytes, so the inner loop stays branch-free and
/// the bit shifts are compile-time constants. The generic LSB-by-LSB
/// loop is kept as a fallback for any other `d` (used only by tests).
pub fn byte_encode(d: usize, coeffs: &[u16; 256], out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d);
    match d {
        12 => encode_d12(coeffs, out),
        10 => encode_d10(coeffs, out),
        4 => encode_d4(coeffs, out),
        1 => encode_d1(coeffs, out),
        _ => encode_generic(d, coeffs, out),
    }
}

/// `ByteDecode_d`: unpack `32·d` bytes into 256 `d`-bit values. For `d = 12`
/// values are reduced mod q (per FIPS 203), matching parsing of an untrusted
/// key; for `d < 12` they are exactly the packed bits.
///
/// Same fast-path dispatch shape as [`byte_encode`].
pub fn byte_decode(d: usize, bytes: &[u8]) -> [u16; 256] {
    debug_assert_eq!(bytes.len(), 32 * d);
    match d {
        12 => decode_d12(bytes),
        10 => decode_d10(bytes),
        4 => decode_d4(bytes),
        1 => decode_d1(bytes),
        _ => decode_generic(d, bytes),
    }
}

/// `d = 12`: every 2 coefficients (24 bits) pack into 3 bytes. The dominant
/// case (matrix vectors, public keys, private keys).
fn encode_d12(coeffs: &[u16; 256], out: &mut [u8]) {
    for (pair_idx, chunk) in out.chunks_exact_mut(3).enumerate() {
        let c0 = coeffs[2 * pair_idx];
        let c1 = coeffs[2 * pair_idx + 1];
        chunk[0] = c0 as u8;
        chunk[1] = ((c0 >> 8) as u8 & 0x0f) | ((c1 as u8 & 0x0f) << 4);
        chunk[2] = (c1 >> 4) as u8;
    }
}

fn decode_d12(bytes: &[u8]) -> [u16; 256] {
    let mut coeffs = [0u16; 256];
    for (pair_idx, chunk) in bytes.chunks_exact(3).enumerate() {
        let b0 = u16::from(chunk[0]);
        let b1 = u16::from(chunk[1]);
        let b2 = u16::from(chunk[2]);
        let c0 = b0 | ((b1 & 0x0f) << 8);
        let c1 = (b1 >> 4) | (b2 << 4);
        coeffs[2 * pair_idx] = c0 % Q as u16;
        coeffs[2 * pair_idx + 1] = c1 % Q as u16;
    }
    coeffs
}

/// `d = 10`: every 4 coefficients (40 bits) pack into 5 bytes. Used for
/// the `u` ciphertext vector (compressed at width `du = 10`).
fn encode_d10(coeffs: &[u16; 256], out: &mut [u8]) {
    for (quad_idx, chunk) in out.chunks_exact_mut(5).enumerate() {
        let c0 = coeffs[4 * quad_idx];
        let c1 = coeffs[4 * quad_idx + 1];
        let c2 = coeffs[4 * quad_idx + 2];
        let c3 = coeffs[4 * quad_idx + 3];
        chunk[0] = c0 as u8;
        chunk[1] = (c0 >> 8) as u8 | ((c1 as u8 & 0x3f) << 2);
        chunk[2] = ((c1 >> 6) as u8 & 0x0f) | ((c2 as u8 & 0x0f) << 4);
        chunk[3] = ((c2 >> 4) as u8 & 0x3f) | ((c3 as u8 & 0x03) << 6);
        chunk[4] = (c3 >> 2) as u8;
    }
}

fn decode_d10(bytes: &[u8]) -> [u16; 256] {
    let mut coeffs = [0u16; 256];
    const MASK10: u16 = 0x3ff;
    for (quad_idx, chunk) in bytes.chunks_exact(5).enumerate() {
        let b0 = u16::from(chunk[0]);
        let b1 = u16::from(chunk[1]);
        let b2 = u16::from(chunk[2]);
        let b3 = u16::from(chunk[3]);
        let b4 = u16::from(chunk[4]);
        coeffs[4 * quad_idx] = b0 | ((b1 & 0x03) << 8);
        coeffs[4 * quad_idx + 1] = ((b1 >> 2) | (b2 << 6)) & MASK10;
        coeffs[4 * quad_idx + 2] = ((b2 >> 4) | (b3 << 4)) & MASK10;
        coeffs[4 * quad_idx + 3] = (b3 >> 6) | (b4 << 2);
    }
    coeffs
}

/// `d = 4`: every 2 coefficients (8 bits) pack into 1 byte. Used for the
/// `v` ciphertext polynomial (compressed at width `dv = 4`).
fn encode_d4(coeffs: &[u16; 256], out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (coeffs[2 * i] as u8 & 0x0f) | ((coeffs[2 * i + 1] as u8 & 0x0f) << 4);
    }
}

fn decode_d4(bytes: &[u8]) -> [u16; 256] {
    let mut coeffs = [0u16; 256];
    for (i, &b) in bytes.iter().enumerate() {
        coeffs[2 * i] = u16::from(b & 0x0f);
        coeffs[2 * i + 1] = u16::from(b >> 4);
    }
    coeffs
}

/// `d = 1`: every 8 coefficients (8 bits) pack into 1 byte — the message
/// bitmap used by `poly_frommsg` / `poly_tomsg`.
fn encode_d1(coeffs: &[u16; 256], out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        let mut b = 0u8;
        for j in 0..8 {
            b |= ((coeffs[8 * i + j] & 1) as u8) << j;
        }
        *byte = b;
    }
}

fn decode_d1(bytes: &[u8]) -> [u16; 256] {
    let mut coeffs = [0u16; 256];
    for (i, &b) in bytes.iter().enumerate() {
        for j in 0..8 {
            coeffs[8 * i + j] = u16::from((b >> j) & 1);
        }
    }
    coeffs
}

/// Generic LSB-first packer — correctness reference, used only for `d`
/// values outside the ML-KEM-768 set (and exercised by the tests).
fn encode_generic(d: usize, coeffs: &[u16; 256], out: &mut [u8]) {
    out.iter_mut().for_each(|b| *b = 0);
    let mut bit = 0usize;
    for &c in coeffs {
        for i in 0..d {
            if (c >> i) & 1 == 1 {
                out[bit / 8] |= 1 << (bit % 8);
            }
            bit += 1;
        }
    }
}

fn decode_generic(d: usize, bytes: &[u8]) -> [u16; 256] {
    let mut coeffs = [0u16; 256];
    let mut bit = 0usize;
    for c in coeffs.iter_mut() {
        let mut val = 0u16;
        for i in 0..d {
            let b = (bytes[bit / 8] >> (bit % 8)) & 1;
            val |= (b as u16) << i;
            bit += 1;
        }
        *c = if d == 12 { val % Q as u16 } else { val };
    }
    coeffs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_range(seed: u64, bound: u16) -> [u16; 256] {
        let mut s = seed;
        core::array::from_fn(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((s >> 33) as u16) % bound
        })
    }

    #[test]
    fn encode_decode_roundtrip() {
        for &d in &[1usize, 4, 10, 11] {
            let coeffs = sample_range(d as u64, 1 << d);
            let mut buf = vec![0u8; 32 * d];
            byte_encode(d, &coeffs, &mut buf);
            assert_eq!(byte_decode(d, &buf), coeffs, "d={d}");
        }
    }

    #[test]
    fn encode_decode_roundtrip_d12_in_range() {
        // d=12 decode reduces mod q, so the round-trip is identity only for
        // inputs already in [0, q).
        let coeffs = sample_range(99, Q as u16);
        let mut buf = vec![0u8; 32 * 12];
        byte_encode(12, &coeffs, &mut buf);
        assert_eq!(byte_decode(12, &buf), coeffs);
    }

    #[test]
    fn compress_decompress_bounds_and_error() {
        // Decompress∘Compress is near-identity: |x' - x| <= round(q / 2^(d+1)).
        for &d in &[4u32, 10] {
            let tol = (Q as i32) / (1 << (d + 1)) + 1;
            for x in (0..Q as u16).step_by(7) {
                let c = compress(d, x);
                assert!(c < (1 << d), "compress in range d={d}");
                let x2 = decompress(d, c) as i32;
                // wrap-around distance mod q
                let diff = ((x2 - x as i32 + Q as i32) % Q as i32)
                    .min((x as i32 - x2 + Q as i32) % Q as i32);
                assert!(diff <= tol, "d={d} x={x} x2={x2} diff={diff} tol={tol}");
            }
        }
    }

    #[test]
    fn compress_1bit_is_rounding_halves() {
        // d=1: the message bit map. x near 0 -> 0, x near q/2 -> 1.
        assert_eq!(compress(1, 0), 0);
        assert_eq!(compress(1, (Q as u16) / 2), 1);
        assert_eq!(decompress(1, 1), (Q as u16).div_ceil(2));
    }
}
