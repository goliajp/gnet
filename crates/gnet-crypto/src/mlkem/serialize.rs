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
pub fn byte_encode(d: usize, coeffs: &[u16; 256], out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d);
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

/// `ByteDecode_d`: unpack `32·d` bytes into 256 `d`-bit values. For `d = 12`
/// values are reduced mod q (per FIPS 203), matching parsing of an untrusted
/// key; for `d < 12` they are exactly the packed bits.
pub fn byte_decode(d: usize, bytes: &[u8]) -> [u16; 256] {
    debug_assert_eq!(bytes.len(), 32 * d);
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
