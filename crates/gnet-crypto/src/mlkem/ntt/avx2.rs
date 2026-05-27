//! AVX2 16-way SIMD for the ML-KEM NTT and base multiplication. Mirror of
//! [`super::neon`] for x86_64 — same butterfly schedule, scalar tail at
//! the inner layers, all entry points bit-identical to the scalar
//! reference (verified by `ntt_avx2_matches_scalar` /
//! `invntt_avx2_matches_scalar` in [`super::tests`]).
//!
//! Lane width: each `__m256i` carries 16 × i16, twice NEON's 8 × i16.
//! The AVX2 path covers the outer four butterfly layers (`len` ∈
//! {128, 64, 32, 16}) — at `len = 8` the per-group stride of 16 doesn't
//! divide the group, so layer 5 also drops to scalar (NEON's 8-way
//! covers it; AVX2's 16-way does not).
//!
//! Montgomery reduction (`fqmul_x16`) follows the canonical
//! pqcrystals-kyber-avx2 pattern: stay in i16 throughout via
//! `mulhi`/`mullo` plus the QINV identity, no i32 widening. Barrett
//! reduction is harder to do in pure i16 because the shift amount
//! (`>> 26`) exceeds what mulhi's `>> 16` gives, so it widens to i32 in
//! two halves, narrows back with `_mm256_packs_epi32`, and applies
//! `_mm256_permute4x64_epi64` to fix the standard AVX2 cross-128-bit-lane
//! ordering that `packs` produces.

#![allow(unsafe_op_in_unsafe_fn)]

use super::{Q, QINV, ZETAS, barrett_reduce, fqmul};
use core::arch::x86_64::{
    __m256i, _mm256_add_epi16, _mm256_add_epi32, _mm256_castsi256_si128,
    _mm256_cvtepi16_epi32, _mm256_extracti128_si256, _mm256_loadu_si256,
    _mm256_mulhi_epi16, _mm256_mullo_epi16, _mm256_mullo_epi32,
    _mm256_packs_epi32, _mm256_permute4x64_epi64, _mm256_set1_epi16,
    _mm256_set1_epi32, _mm256_srai_epi32, _mm256_storeu_si256,
    _mm256_sub_epi16,
};

/// `a · b · 2^-16 mod q` over 16 lanes. Matches [`super::fqmul`]
/// bit-for-bit per lane.
///
/// Implementation: pqcrystals-kyber-avx2's `fqmul` — keep everything in
/// i16 by computing `(P - t·Q) >> 16` as `mulhi(a,b) -
/// mulhi(mullo(a,b)·QINV, Q)`. Works because `Q·QINV ≡ 1 mod 2^16`, so
/// the low 16 of `P - t·Q` is zero by construction, and the >> 16 reduces
/// to a subtraction of the high halves of the two i32 products.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn fqmul_x16(a: __m256i, b: __m256i) -> __m256i {
    let qinv_v = _mm256_set1_epi16(QINV);
    let q_v = _mm256_set1_epi16(Q);
    let lo = _mm256_mullo_epi16(a, b);
    let hi = _mm256_mulhi_epi16(a, b);
    let t = _mm256_mullo_epi16(lo, qinv_v);
    let t_q = _mm256_mulhi_epi16(t, q_v);
    _mm256_sub_epi16(hi, t_q)
}

/// Barrett-reduce 16 i16 to representatives in `(-q/2, q/2]`. Matches
/// [`super::barrett_reduce`] bit-for-bit per lane.
///
/// The shift amount in scalar Barrett (`>> 26`) is wider than what
/// `mulhi`'s `>> 16` provides directly, so we widen each 16 i16 to two
/// i32 halves (8 + 8 lanes), do `V·a + (1<<25)` and `>> 26` in i32,
/// then narrow back with `_mm256_packs_epi32` + a
/// `_mm256_permute4x64_epi64` to undo the cross-lane interleaving that
/// `packs` produces.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn barrett_reduce_x16(a: __m256i) -> __m256i {
    // V = floor(2^26 / q) — same constant as super::barrett_reduce.
    const V: i32 = 20159;
    let v_v = _mm256_set1_epi32(V);
    let round_v = _mm256_set1_epi32(1 << 25);
    let q_v = _mm256_set1_epi16(Q);

    // Widen 16 i16 -> two halves of 8 i32 each. _mm256_cvtepi16_epi32
    // takes __m128i (8 × i16) and returns __m256i (8 × i32).
    let a_lo128 = _mm256_castsi256_si128(a);              // i16 lanes 0..7
    let a_hi128 = _mm256_extracti128_si256::<1>(a);       // i16 lanes 8..15
    let a_lo32 = _mm256_cvtepi16_epi32(a_lo128);          // i32 lanes 0..7
    let a_hi32 = _mm256_cvtepi16_epi32(a_hi128);          // i32 lanes 8..15

    // (V·a + round) >> 26 — arithmetic shift preserves sign.
    let prod_lo = _mm256_mullo_epi32(v_v, a_lo32);
    let prod_hi = _mm256_mullo_epi32(v_v, a_hi32);
    let plus_lo = _mm256_add_epi32(prod_lo, round_v);
    let plus_hi = _mm256_add_epi32(prod_hi, round_v);
    let t_lo = _mm256_srai_epi32::<26>(plus_lo);
    let t_hi = _mm256_srai_epi32::<26>(plus_hi);

    // Pack 8+8 i32 -> 16 i16. _mm256_packs_epi32 produces the
    // cross-128-bit-lane interleave [a0..3, b0..3, a4..7, b4..7];
    // permute4x64 with imm8 = 0xD8 (binary 11_01_10_00) swaps qwords 1<->2,
    // restoring [a0..3, a4..7, b0..3, b4..7] = sequential 0..15 i16 order.
    let packed = _mm256_packs_epi32(t_lo, t_hi);
    let t = _mm256_permute4x64_epi64::<0xD8>(packed);

    _mm256_sub_epi16(a, _mm256_mullo_epi16(t, q_v))
}

/// One SIMD-able layer of the forward NTT (`len ≥ 16`): every butterfly
/// in a single (start, start+len) group uses the same zeta, so we
/// broadcast it once and process 16 butterflies per `__m256i`.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
unsafe fn ntt_layer_uniform(
    r: &mut [i16; 256],
    start: usize,
    len: usize,
    zeta: i16,
) {
    let z_v = _mm256_set1_epi16(zeta);
    let mut j = start;
    while j < start + len {
        let lo_ptr = r.as_ptr().add(j) as *const __m256i;
        let hi_ptr = r.as_ptr().add(j + len) as *const __m256i;
        let rj = _mm256_loadu_si256(lo_ptr);
        let rj_len = _mm256_loadu_si256(hi_ptr);
        let t = fqmul_x16(z_v, rj_len);
        let new_rj = _mm256_add_epi16(rj, t);
        let new_rj_len = _mm256_sub_epi16(rj, t);
        _mm256_storeu_si256(r.as_mut_ptr().add(j) as *mut __m256i, new_rj);
        _mm256_storeu_si256(r.as_mut_ptr().add(j + len) as *mut __m256i, new_rj_len);
        j += 16;
    }
}

/// One SIMD-able layer of the inverse NTT (`len ≥ 16`): same
/// uniform-zeta pattern; butterfly form is `r[j] = barrett(t + r[j+len]);
/// r[j+len] = fqmul(zeta, r[j+len] − t)` with `t = r[j]` captured first.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
unsafe fn invntt_layer_uniform(
    r: &mut [i16; 256],
    start: usize,
    len: usize,
    zeta: i16,
) {
    let z_v = _mm256_set1_epi16(zeta);
    let mut j = start;
    while j < start + len {
        let lo_ptr = r.as_ptr().add(j) as *const __m256i;
        let hi_ptr = r.as_ptr().add(j + len) as *const __m256i;
        let t = _mm256_loadu_si256(lo_ptr);
        let rj_len = _mm256_loadu_si256(hi_ptr);
        let sum = _mm256_add_epi16(t, rj_len);
        let new_rj = barrett_reduce_x16(sum);
        let diff = _mm256_sub_epi16(rj_len, t);
        let new_rj_len = fqmul_x16(z_v, diff);
        _mm256_storeu_si256(r.as_mut_ptr().add(j) as *mut __m256i, new_rj);
        _mm256_storeu_si256(r.as_mut_ptr().add(j + len) as *mut __m256i, new_rj_len);
        j += 16;
    }
}

/// SIMD forward NTT: outer 4 layers (`len ∈ {128, 64, 32, 16}`) via
/// AVX2 16-way butterflies; inner 3 layers (`len ∈ {8, 4, 2}`) scalar.
/// AVX2 covers one fewer layer than NEON because the wider 16-element
/// stride doesn't fit the `len = 8` group (each group spans only 16
/// elements, exactly one stride — handled by NEON's 8-way; the AVX2
/// 16-way's first iteration would already overflow the group).
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn ntt_avx2(r: &mut [i16; 256]) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 16 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            ntt_layer_uniform(r, start, len, zeta);
            start += 2 * len;
        }
        len >>= 1;
    }
    // Layers len = 8, 4, 2 scalar tail. Matches super::ntt_scalar.
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// SIMD inverse NTT: inner 3 layers (`len ∈ {2, 4, 8}`) scalar, outer
/// 4 layers (`len ∈ {16, 32, 64, 128}`) AVX2, final `F = 2^32/128 mod q`
/// Montgomery scaling vectorised over 16 i16x16 batches.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn invntt_avx2(r: &mut [i16; 256]) {
    const F: i16 = 1441;
    let mut k = 127usize;
    let mut len = 2usize;
    // Layers len = 2, 4, 8 scalar (per-group stride < SIMD width).
    while len < 16 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] -= t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // Layers len = 16..=128: SIMD.
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            // ZETAS underflow guard: when k = 0 we've consumed the last
            // zeta. The next len doubles past 128 so the outer while
            // exits before any further decrement.
            k = k.wrapping_sub(1);
            invntt_layer_uniform(r, start, len, zeta);
            start += 2 * len;
        }
        len <<= 1;
    }
    // F-scaling over all 256 coefficients in i16x16 strides.
    let f_v = _mm256_set1_epi16(F);
    let mut j = 0usize;
    while j < 256 {
        let rj = _mm256_loadu_si256(r.as_ptr().add(j) as *const __m256i);
        let scaled = fqmul_x16(f_v, rj);
        _mm256_storeu_si256(r.as_mut_ptr().add(j) as *mut __m256i, scaled);
        j += 16;
    }
}
