//! NEON 8-way SIMD for the ML-KEM NTT and base multiplication. Each of the
//! three public entry points ([`ntt_neon`], [`invntt_neon`],
//! [`ntt_mul_into_neon`]) is bit-identical to its scalar counterpart in
//! [`super`] — verified by the `_matches_scalar` tests in [`super::tests`].
//!
//! The outermost five butterfly layers (`len` ∈ {128, 64, 32, 16, 8}) all
//! share a single zeta per group, so we broadcast it into a `uint64x2_t`
//! and process 8 butterflies per loop iteration. The two innermost layers
//! (`len` ∈ {4, 2}) need different zetas inside one int16x8_t lane group;
//! the shuffle cost to assemble the mixed-zeta vector outweighs the SIMD
//! win at those sizes, so those layers stay scalar.
//!
//! `ntt_mul_into_neon` processes 4 of the scalar reference's loop
//! iterations at a time (= 8 base mults = 16 output coefficients), using
//! `vld2q_s16` / `vst2q_s16` to (de-)interleave the per-pair coefficients
//! and a pre-computed alternating-sign zeta table for the `lo basemul
//! uses +z, hi basemul uses −z` rule.

use super::{Q, QINV, ZETAS, barrett_reduce, fqmul};
use core::arch::aarch64::*;

/// Montgomery reduce eight i32 inputs (held as two int32x4_t halves) to
/// eight i16 outputs in `(-q, q)`. Matches `super::montgomery_reduce`
/// lane-for-lane.
///
/// # Safety
/// NEON intrinsics; available unconditionally on aarch64.
#[inline]
pub(super) unsafe fn montgomery_reduce_x8(lo: int32x4_t, hi: int32x4_t) -> int16x8_t {
    unsafe {
        let qinv_v = vdupq_n_s16(QINV);
        // a_low16: truncate each i32 to its low 16 bits (signed).
        let a_low = vcombine_s16(vmovn_s32(lo), vmovn_s32(hi));
        // t (i16) = a_low * QINV (wrapping; low 16 of full product).
        let t_i16 = vmulq_s16(a_low, qinv_v);
        // tQ as i32 = t (i16, sign-extended) * Q.
        let q_v = vdup_n_s16(Q);
        let t_q_lo = vmull_s16(vget_low_s16(t_i16), q_v);
        let t_q_hi = vmull_s16(vget_high_s16(t_i16), q_v);
        // (a - tQ) >> 16: vshrn does the shift+narrow in one instruction.
        let diff_lo = vsubq_s32(lo, t_q_lo);
        let diff_hi = vsubq_s32(hi, t_q_hi);
        vcombine_s16(vshrn_n_s32::<16>(diff_lo), vshrn_n_s32::<16>(diff_hi))
    }
}

/// `a · b · 2^-16 mod q` over 8 lanes. Matches `super::fqmul`.
///
/// # Safety
/// NEON intrinsics; aarch64-only.
#[inline]
pub(super) unsafe fn fqmul_x8(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    unsafe {
        let prod_lo = vmull_s16(vget_low_s16(a), vget_low_s16(b));
        let prod_hi = vmull_high_s16(a, b);
        montgomery_reduce_x8(prod_lo, prod_hi)
    }
}

/// Barrett-reduce eight i16 to representatives in `(-q/2, q/2]`. Matches
/// `super::barrett_reduce`.
///
/// # Safety
/// NEON intrinsics; aarch64-only.
#[inline]
pub(super) unsafe fn barrett_reduce_x8(a: int16x8_t) -> int16x8_t {
    unsafe {
        // V = floor(2^26 / q)  (matches super::barrett_reduce).
        const V: i32 = 20159;
        let v_v = vdupq_n_s32(V);
        let round_v = vdupq_n_s32(1 << 25);
        let q_v = vdupq_n_s16(Q);

        let a_lo = vmovl_s16(vget_low_s16(a));
        let a_hi = vmovl_high_s16(a);
        let prod_lo = vmlaq_s32(round_v, v_v, a_lo);
        let prod_hi = vmlaq_s32(round_v, v_v, a_hi);
        // vshrn_n_s32::<N> requires N ∈ [1, 16]; 26 is out of range.
        // Do the >> 26 with vshrq (32-bit shift, N up to 32) then
        // narrow to i16 with vmovn.
        let t_lo32 = vshrq_n_s32::<26>(prod_lo);
        let t_hi32 = vshrq_n_s32::<26>(prod_hi);
        let t = vcombine_s16(vmovn_s32(t_lo32), vmovn_s32(t_hi32));
        vsubq_s16(a, vmulq_s16(t, q_v))
    }
}

/// One SIMD-able layer of the forward NTT (`len ≥ 8`): every butterfly
/// in a single (start, start+len) group uses the same zeta, so we
/// broadcast it once and process 8 butterflies per int16x8_t.
///
/// # Safety
/// NEON intrinsics; aarch64-only.
#[inline]
unsafe fn ntt_layer_uniform(r: &mut [i16; 256], start: usize, len: usize, zeta: i16) {
    unsafe {
        let z_v = vdupq_n_s16(zeta);
        let mut j = start;
        while j < start + len {
            let ptr_lo = r.as_ptr().add(j);
            let ptr_hi = r.as_ptr().add(j + len);
            let rj = vld1q_s16(ptr_lo);
            let rj_len = vld1q_s16(ptr_hi);
            let t = fqmul_x8(z_v, rj_len);
            let new_rj = vaddq_s16(rj, t);
            let new_rj_len = vsubq_s16(rj, t);
            vst1q_s16(r.as_mut_ptr().add(j), new_rj);
            vst1q_s16(r.as_mut_ptr().add(j + len), new_rj_len);
            j += 8;
        }
    }
}

/// One SIMD-able layer of the inverse NTT (`len ≥ 8`): same uniform-zeta
/// pattern as the forward; butterfly form is `r[j] = barrett(t +
/// r[j+len]); r[j+len] = fqmul(zeta, r[j+len] - t)` (with `t = r[j]`
/// captured first).
///
/// # Safety
/// NEON intrinsics; aarch64-only.
#[inline]
unsafe fn invntt_layer_uniform(r: &mut [i16; 256], start: usize, len: usize, zeta: i16) {
    unsafe {
        let z_v = vdupq_n_s16(zeta);
        let mut j = start;
        while j < start + len {
            let ptr_lo = r.as_ptr().add(j);
            let ptr_hi = r.as_ptr().add(j + len);
            let t = vld1q_s16(ptr_lo);
            let rj_len = vld1q_s16(ptr_hi);
            let sum = vaddq_s16(t, rj_len);
            let new_rj = barrett_reduce_x8(sum);
            let diff = vsubq_s16(rj_len, t);
            let new_rj_len = fqmul_x8(z_v, diff);
            vst1q_s16(r.as_mut_ptr().add(j), new_rj);
            vst1q_s16(r.as_mut_ptr().add(j + len), new_rj_len);
            j += 8;
        }
    }
}

/// SIMD forward NTT: outer 5 layers (`len` = 128, 64, 32, 16, 8) via
/// NEON 8-way butterflies; inner 2 layers (`len` = 4, 2) scalar.
pub(super) fn ntt_neon(r: &mut [i16; 256]) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 8 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            // SAFETY: aarch64-only; len is power-of-two ≥ 8 so the
            // inner loop strides by 8 cleanly within a 256-element slice.
            unsafe {
                ntt_layer_uniform(r, start, len, zeta);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    // Layers len = 4, 2: scalar tail. Matches super::ntt_scalar.
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

/// SIMD inverse NTT: inner 2 layers (`len` = 2, 4) scalar, outer 5
/// layers (`len` = 8, 16, 32, 64, 128) NEON, final `F = 2^32/128 mod q`
/// Montgomery scaling vectorized over 32 i16x8 batches.
pub(super) fn invntt_neon(r: &mut [i16; 256]) {
    const F: i16 = 1441;
    let mut k = 127usize;
    let mut len = 2usize;
    // Layers len = 2, 4: scalar (lane-shuffle cost outweighs SIMD win).
    while len < 8 {
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
    // Layers len = 8..=128: SIMD.
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            // ZETAS underflow guard: when k = 0 we've consumed the last
            // zeta in the schedule. The next len doubles past 128 so
            // the outer while exits before any further decrement.
            k = k.wrapping_sub(1);
            // SAFETY: aarch64-only; len ≥ 8 so strides cleanly.
            unsafe {
                invntt_layer_uniform(r, start, len, zeta);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // F-scaling: r *= F · 2^-16 mod q over all 256 coefficients.
    // SAFETY: aarch64-only; iterates in i16x8 strides over a 256-element
    // slice.
    unsafe {
        let f_v = vdupq_n_s16(F);
        let mut j = 0usize;
        while j < 256 {
            let rj = vld1q_s16(r.as_ptr().add(j));
            let scaled = fqmul_x8(f_v, rj);
            vst1q_s16(r.as_mut_ptr().add(j), scaled);
            j += 8;
        }
    }
}

/// Pre-computed zeta vectors for [`ntt_mul_into_neon`], one
/// `int16x8_t`-shaped row per 4 base multiplications (16 rows total
/// covering the 64 base muls). Each row is `[+z0, -z0, +z1, -z1, +z2,
/// -z2, +z3, -z3]` where `zk = ZETAS[64 + 4*si + k]` for SIMD index `si`
/// — the alternating ± pattern handles the `lo basemul uses +z, hi
/// basemul uses -z` rule from the scalar reference in lockstep.
const fn build_zeta_mul_vecs() -> [[i16; 8]; 16] {
    let mut out = [[0i16; 8]; 16];
    let mut si = 0;
    while si < 16 {
        let mut k = 0;
        while k < 4 {
            let z = ZETAS[64 + 4 * si + k];
            out[si][2 * k] = z;
            out[si][2 * k + 1] = -z;
            k += 1;
        }
        si += 1;
    }
    out
}
static ZETA_MUL_VECS: [[i16; 8]; 16] = build_zeta_mul_vecs();

/// NEON 8-way pointwise multiplication in the NTT domain. Processes 4
/// loop iterations of the scalar reference at a time (= 8 base mults =
/// 16 output coefficients per SIMD step). On each step:
///
/// - `vld2q_s16` de-interleaves 16 source coefficients of `a` (and `b`)
///   into "even" (per-pair index 0) and "odd" (per-pair index 1)
///   `int16x8_t` lanes.
/// - The base-mul formulas (`c0 = a0·b0 + zeta·a1·b1` and
///   `c1 = a0·b1 + a1·b0`) run over 8 lanes simultaneously, using
///   [`fqmul_x8`] for each Montgomery multiply.
/// - `vst2q_s16` re-interleaves the resulting `(c0, c1)` pair back into
///   16 contiguous output coefficients.
///
/// Matches the scalar `super::ntt_mul_into_scalar` bit-for-bit on every
/// input; verified by `ntt_mul_neon_matches_scalar` in the test module.
pub(super) fn ntt_mul_into_neon(a: &[i16; 256], b: &[i16; 256], r: &mut [i16; 256]) {
    // SAFETY: aarch64-only module; ptr arithmetic is bounded by the
    // 16-i16 stride over a 256-element slice (16 iters × 16 i16 = 256).
    unsafe {
        for (si, zetas) in ZETA_MUL_VECS.iter().enumerate() {
            let off = si * 16;
            let a_pair = vld2q_s16(a.as_ptr().add(off));
            let b_pair = vld2q_s16(b.as_ptr().add(off));
            let a_even = a_pair.0;
            let a_odd = a_pair.1;
            let b_even = b_pair.0;
            let b_odd = b_pair.1;

            let zeta_vec = vld1q_s16(zetas.as_ptr());

            // c0 = a_even * b_even + zeta * (a_odd * b_odd)
            let aobo = fqmul_x8(a_odd, b_odd);
            let zaobo = fqmul_x8(zeta_vec, aobo);
            let aebe = fqmul_x8(a_even, b_even);
            let c0 = vaddq_s16(aebe, zaobo);

            // c1 = a_even * b_odd + a_odd * b_even
            let aebo = fqmul_x8(a_even, b_odd);
            let aobe = fqmul_x8(a_odd, b_even);
            let c1 = vaddq_s16(aebo, aobe);

            vst2q_s16(r.as_mut_ptr().add(off), int16x8x2_t(c0, c1));
        }
    }
}
