//! Fixed-base X25519: `scalar · 9` (Montgomery basepoint) via an Edwards
//! comb table. ~4× faster than [`super::scalar::x25519`] for the
//! public-key-derivation case while preserving the same 32-byte LE
//! input / output API.
//!
//! Algorithm
//! 1. RFC 7748 §5 clamp.
//! 2. 4-bit signed-digit recoding of the 256-bit scalar into 64 digits
//!    in `[-7, 8]`. The recoding is branch-free over scalar bits; the
//!    carry-out is always 0 for a clamped scalar (top nibble + carry ≤ 8).
//! 3. For each window `i`, constant-time select of the `|d_i|`-th cached
//!    Edwards multiple from [`super::base_table::TABLE`]`[i]`, conditional
//!    negate by `sign(d_i)`, and `ed_mixed_add` into the running
//!    extended-coords accumulator.
//! 4. Project the result back to the Curve25519 u-axis via the birational
//!    map `u = (Z + Y) / (Z - Y)` and serialize little-endian.

use super::base_table::{TABLE, WINDOWS};
use super::edwards::{
    IDENTITY, ct_negate_cached, ct_select_cached, ed_mixed_add, ed_to_mont_u,
};
use super::scalar::clamp;

/// X25519 fixed-base: `scalar · 9` on the Curve25519 u-axis.
///
/// Equivalent to `x25519(scalar, &[9, 0, ..., 0])` but uses a
/// compile-time-precomputed Edwards basepoint comb (~60 KiB `.rodata`)
/// and runs ≈ 4× faster on the hot path. Use this for public-key
/// derivation; the general [`super::x25519`] handles the DH step.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut s = *scalar;
    clamp(&mut s);
    let digits = recode_signed_4bit(&s);

    let mut acc = IDENTITY;
    for i in 0..WINDOWS {
        let d = digits[i];
        let abs_d = d.unsigned_abs();
        // neg_mask: 0 if d >= 0, u64::MAX if d < 0. Branch-free via the
        // sign extension of the i64 cast.
        let neg_mask = (i64::from(d) >> 63) as u64;
        let mut p = ct_select_cached(&TABLE[i], abs_d);
        ct_negate_cached(&mut p, neg_mask);
        acc = ed_mixed_add(&acc, &p);
    }

    ed_to_mont_u(&acc)
}

/// 4-bit signed-digit recoding of the (clamped) scalar.
///
/// Splits the 256-bit input into 64 four-bit nibbles low-to-high, then
/// folds carries so each emitted digit lies in `[-7, 8]`. All operations
/// are data-flow (no conditional branches on scalar bits), so the
/// recoding does not leak secret bits through timing.
fn recode_signed_4bit(s: &[u8; 32]) -> [i8; 64] {
    let mut digits = [0i8; 64];
    let mut carry: i8 = 0;
    for i in 0..64 {
        let nibble_raw = (s[i / 2] >> (((i as u8) & 1) * 4)) & 0x0f;
        let nibble = (nibble_raw as i8) + carry;
        // If nibble >= 9 emit (nibble − 16) with carry 1; else keep.
        // Branch-free: `(nibble + 7) >> 4` is 0 for nibble ≤ 8, 1 for ≥ 9.
        let carry_next = (nibble + 7) >> 4;
        digits[i] = nibble - (carry_next << 4);
        carry = carry_next;
    }
    // Clamped X25519 scalars (bit 254 set, bit 255 clear) cannot overflow
    // past the 64th window: top nibble ∈ {4,5,6,7} + carry_in ∈ {0,1} ≤ 8.
    debug_assert_eq!(carry, 0);
    digits
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::scalar::x25519;

    fn base_point() -> [u8; 32] {
        let mut u = [0u8; 32];
        u[0] = 9;
        u
    }

    /// RFC 7748 §6.1 — Alice's public key from her secret via fixed-base.
    #[test]
    fn rfc7748_alice_public_key_via_basepoint_comb() {
        let priv_key = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(x25519_base(&priv_key), expected);
    }

    /// RFC 7748 §6.1 — Bob's public key from his secret via fixed-base.
    #[test]
    fn rfc7748_bob_public_key_via_basepoint_comb() {
        let priv_key = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        assert_eq!(x25519_base(&priv_key), expected);
    }

    /// Across 64 deterministic random scalars, `x25519_base(s)` must
    /// agree bit-for-bit with the Montgomery ladder `x25519(s, &[9, 0, …, 0])`.
    /// This is the load-bearing differential test.
    #[test]
    fn x25519_base_matches_montgomery_ladder_across_random_scalars() {
        let basepoint = base_point();
        // xorshift64 seeded with a fixed value for reproducibility.
        let mut state: u64 = 0xdead_beef_cafe_babe;
        for _ in 0..64 {
            let mut scalar = [0u8; 32];
            for chunk in scalar.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            let comb = x25519_base(&scalar);
            let ladder = x25519(&scalar, &basepoint);
            assert_eq!(comb, ladder, "comb vs ladder disagreement");
        }
    }

    #[test]
    fn x25519_base_matches_ladder_for_all_zero_scalar() {
        let s = [0u8; 32];
        assert_eq!(x25519_base(&s), x25519(&s, &base_point()));
    }

    #[test]
    fn x25519_base_matches_ladder_for_all_ones_scalar() {
        let s = [0xffu8; 32];
        assert_eq!(x25519_base(&s), x25519(&s, &base_point()));
    }

    #[test]
    fn recoding_round_trip_arbitrary_scalar() {
        // recode_signed_4bit operates on the raw scalar (no clamp). The
        // signed-digit sum must equal the input scalar mod 2^256.
        let s = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let digits = recode_signed_4bit(&s);
        // Fold digits back: acc[byte] += d << shift; then propagate carries.
        let mut acc = [0i64; 33];
        for (i, d) in digits.iter().enumerate() {
            let byte_idx = i / 2;
            let shift = (i & 1) * 4;
            acc[byte_idx] += i64::from(*d) << shift;
        }
        for k in 0..32 {
            let v = acc[k];
            // signed carry-propagate one byte at a time
            let low = v.rem_euclid(256);
            let high = (v - low) / 256;
            acc[k] = low;
            acc[k + 1] += high;
        }
        let mut got = [0u8; 32];
        for k in 0..32 {
            assert!(
                (0..256).contains(&acc[k]),
                "carry leak at byte {k}: {:?}",
                acc[k]
            );
            got[k] = acc[k] as u8;
        }
        assert_eq!(got, s);
    }
}
