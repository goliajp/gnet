//! Four-way AVX2 Poly1305 bulk evaluation (x86_64, runtime-detected).
//!
//! Scalar Poly1305 is a Horner chain `acc = (acc + n_i)·r`, each block
//! depending on the previous accumulator. Precomputing `r .. r^4` lets four
//! blocks combine as
//!
//! ```text
//! acc = (acc + n0)·r^4 + n1·r^3 + n2·r^2 + n3·r
//! ```
//!
//! whose four field multiplies are independent. We place those four multiplies
//! across the four 64-bit lanes of a `__m256i`: lane 0 holds `(acc+n0)·r^4`,
//! lane 1 `n1·r^3`, lane 2 `n2·r^2`, lane 3 `n3·r`. Each 26-bit limb product
//! is a `_mm256_mul_epu32` (32×32→64, exact for 26-bit inputs); the five
//! product columns are summed across lanes once per group, then reduced by the
//! shared scalar [`reduce_products`](super::reduce_products) — identical
//! arithmetic to the per-block path, so the differential test pins them
//! together.

use core::arch::x86_64::{
    __m256i, _mm_add_epi64, _mm_cvtsi128_si64, _mm_unpackhi_epi64, _mm256_add_epi64,
    _mm256_castsi256_si128, _mm256_extracti128_si256, _mm256_mul_epu32, _mm256_set_epi64x,
};

use super::{MASK, fmul5, load_le32, mul5, reduce_products};

/// Read a full 16-byte block into five 26-bit limbs with the implicit 2^128
/// bit set (full-block path only — the partial tail block uses the scalar
/// state).
fn block_to_limbs(blk: &[u8]) -> [u64; 5] {
    let t0 = load_le32(&blk[0..4]);
    let t1 = load_le32(&blk[4..8]);
    let t2 = load_le32(&blk[8..12]);
    let t3 = load_le32(&blk[12..16]);
    [
        t0 & MASK,
        ((t0 >> 26) | (t1 << 6)) & MASK,
        ((t1 >> 20) | (t2 << 12)) & MASK,
        ((t2 >> 14) | (t3 << 18)) & MASK,
        (t3 >> 8) | (1 << 24),
    ]
}

/// Sum the four 64-bit lanes of `v`.
///
/// # Safety
/// Requires AVX2 (the 256→128 extract). Called only from [`accumulate`].
#[target_feature(enable = "avx2")]
unsafe fn hsum4(v: __m256i) -> u64 {
    let lo = _mm256_castsi256_si128(v);
    let hi = _mm256_extracti128_si256::<1>(v);
    let s = _mm_add_epi64(lo, hi); // [l0+l2, l1+l3]
    let sh = _mm_unpackhi_epi64(s, s); // [l1+l3, l1+l3]
    _mm_cvtsi128_si64(_mm_add_epi64(s, sh)) as u64
}

/// Evaluate the four-block r-power path over whole 64-byte groups of `msg`
/// (its length must be a multiple of 64) starting from accumulator `init`,
/// returning the updated accumulator in five 26-bit limbs.
///
/// # Safety
/// The CPU must support AVX2 (the caller checks `is_x86_feature_detected!`).
#[target_feature(enable = "avx2")]
pub unsafe fn accumulate(r: &[u64; 5], init: [u64; 5], msg: &[u8]) -> [u64; 5] {
    // key powers, lane order [r^4, r^3, r^2, r] — scalar field arithmetic.
    let r2 = fmul5(r, r, &mul5(r));
    let r3 = fmul5(&r2, r, &mul5(r));
    let r4 = fmul5(&r2, &r2, &mul5(&r2));
    let pow = [r4, r3, r2, *r];
    let pow5 = [mul5(&r4), mul5(&r3), mul5(&r2), mul5(r)];

    unsafe {
        // constant lane vectors: vb[k] lane i = pow[i][k]; vb5[j] lane i = pow5[i][j].
        let vb = |k: usize| {
            _mm256_set_epi64x(
                pow[3][k] as i64,
                pow[2][k] as i64,
                pow[1][k] as i64,
                pow[0][k] as i64,
            )
        };
        let vb5 = |j: usize| {
            _mm256_set_epi64x(
                pow5[3][j] as i64,
                pow5[2][j] as i64,
                pow5[1][j] as i64,
                pow5[0][j] as i64,
            )
        };
        let (vb0, vb1, vb2, vb3, vb4) = (vb(0), vb(1), vb(2), vb(3), vb(4));
        let (vb5_0, vb5_1, vb5_2, vb5_3) = (vb5(0), vb5(1), vb5(2), vb5(3));

        let mut acc = init;
        for group in msg.chunks_exact(64) {
            let n0 = block_to_limbs(&group[0..16]);
            let n1 = block_to_limbs(&group[16..32]);
            let n2 = block_to_limbs(&group[32..48]);
            let n3 = block_to_limbs(&group[48..64]);
            // a-operands: lane 0 = acc + n0, lanes 1..3 = n1, n2, n3.
            let va = |k: usize| {
                _mm256_set_epi64x(
                    n3[k] as i64,
                    n2[k] as i64,
                    n1[k] as i64,
                    (acc[k] + n0[k]) as i64,
                )
            };
            let (va0, va1, va2, va3, va4) = (va(0), va(1), va(2), va(3), va(4));

            // product columns (mirrors super::products), summed lane-wise.
            let d0 = add5(
                _mm256_mul_epu32(va0, vb0),
                _mm256_mul_epu32(va1, vb5_3),
                _mm256_mul_epu32(va2, vb5_2),
                _mm256_mul_epu32(va3, vb5_1),
                _mm256_mul_epu32(va4, vb5_0),
            );
            let d1 = add5(
                _mm256_mul_epu32(va0, vb1),
                _mm256_mul_epu32(va1, vb0),
                _mm256_mul_epu32(va2, vb5_3),
                _mm256_mul_epu32(va3, vb5_2),
                _mm256_mul_epu32(va4, vb5_1),
            );
            let d2 = add5(
                _mm256_mul_epu32(va0, vb2),
                _mm256_mul_epu32(va1, vb1),
                _mm256_mul_epu32(va2, vb0),
                _mm256_mul_epu32(va3, vb5_3),
                _mm256_mul_epu32(va4, vb5_2),
            );
            let d3 = add5(
                _mm256_mul_epu32(va0, vb3),
                _mm256_mul_epu32(va1, vb2),
                _mm256_mul_epu32(va2, vb1),
                _mm256_mul_epu32(va3, vb0),
                _mm256_mul_epu32(va4, vb5_3),
            );
            let d4 = add5(
                _mm256_mul_epu32(va0, vb4),
                _mm256_mul_epu32(va1, vb3),
                _mm256_mul_epu32(va2, vb2),
                _mm256_mul_epu32(va3, vb1),
                _mm256_mul_epu32(va4, vb0),
            );

            acc = reduce_products([hsum4(d0), hsum4(d1), hsum4(d2), hsum4(d3), hsum4(d4)]);
        }
        acc
    }
}

/// Lane-wise sum of five product vectors.
///
/// # Safety
/// Requires AVX2. Called only from within [`accumulate`].
#[target_feature(enable = "avx2")]
unsafe fn add5(a: __m256i, b: __m256i, c: __m256i, d: __m256i, e: __m256i) -> __m256i {
    _mm256_add_epi64(
        _mm256_add_epi64(_mm256_add_epi64(a, b), _mm256_add_epi64(c, d)),
        e,
    )
}
