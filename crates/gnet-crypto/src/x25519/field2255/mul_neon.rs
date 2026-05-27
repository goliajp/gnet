//! NEON 2-way Fe2255 multiplication for aarch64 — the SIMD payoff path
//! of the radix-2^25.5 representation.
//!
//! [`fmul_pair_neon`] takes **two independent fmul operations** and
//! executes them lockstep across the 100 schoolbook cross-products via
//! `vmull_s32` (signed 32×32 → 64-bit widen mul, NEON's only widening
//! integer mul, processes 2 lanes per instruction). Each Fe2255 limb is
//! held in an `int32x2_t` register with lane 0 = stream 1, lane 1 =
//! stream 2; every cross-product then advances both streams in one
//! instruction.
//!
//! Designed primarily for `x25519_base_pair` — the natural call site
//! that has two scalar mults to do simultaneously.
//!
//! Validation: [`super::tests::fmul_pair_neon_matches_two_scalars`]
//! confirms NEON output is bit-exact with two serial scalar
//! `super::fmul` calls on 32 random pairs.

use super::Fe2255;
use core::arch::aarch64::*;

/// Pair fmul: returns `(a1 · b1, a2 · b2)` via NEON 2-way schoolbook.
///
/// # Safety
/// aarch64-only module — NEON intrinsics are always available there.
/// All inputs/outputs are pure registers / stack arrays; no raw pointer
/// dereferences outside `vld1_s32` / `vst1_s32` to fixed `[i32; 2]`
/// stack buffers.
#[inline]
pub(in super::super) fn fmul_pair_neon(
    a1: &Fe2255,
    b1: &Fe2255,
    a2: &Fe2255,
    b2: &Fe2255,
) -> (Fe2255, Fe2255) {
    // SAFETY: see module-level note above.
    unsafe { fmul_pair_neon_inner(a1, b1, a2, b2) }
}

#[inline]
unsafe fn fmul_pair_neon_inner(
    a1: &Fe2255,
    b1: &Fe2255,
    a2: &Fe2255,
    b2: &Fe2255,
) -> (Fe2255, Fe2255) {
    // Pack each limb as int32x2_t — lane 0 = stream 1, lane 1 = stream 2.
    // vld1_s32 loads 2 consecutive i32s from a buffer; we build the
    // 2-element buffer per limb here.
    let pair_limb = |x: i32, y: i32| -> int32x2_t {
        // SAFETY: vld1_s32 reads exactly 2 i32 from `arr`'s 8-byte stack
        // region.
        unsafe {
            let arr: [i32; 2] = [x, y];
            vld1_s32(arr.as_ptr())
        }
    };

    let a = [
        pair_limb(a1[0], a2[0]),
        pair_limb(a1[1], a2[1]),
        pair_limb(a1[2], a2[2]),
        pair_limb(a1[3], a2[3]),
        pair_limb(a1[4], a2[4]),
        pair_limb(a1[5], a2[5]),
        pair_limb(a1[6], a2[6]),
        pair_limb(a1[7], a2[7]),
        pair_limb(a1[8], a2[8]),
        pair_limb(a1[9], a2[9]),
    ];
    let b = [
        pair_limb(b1[0], b2[0]),
        pair_limb(b1[1], b2[1]),
        pair_limb(b1[2], b2[2]),
        pair_limb(b1[3], b2[3]),
        pair_limb(b1[4], b2[4]),
        pair_limb(b1[5], b2[5]),
        pair_limb(b1[6], b2[6]),
        pair_limb(b1[7], b2[7]),
        pair_limb(b1[8], b2[8]),
        pair_limb(b1[9], b2[9]),
    ];

    // SAFETY: aarch64-only. vmul_n_s32 broadcasts the scalar across both lanes.
    let b_19 = unsafe {
        [
            b[0], // unused at *19 in the schedule below, kept for indexing convenience
            vmul_n_s32(b[1], 19),
            vmul_n_s32(b[2], 19),
            vmul_n_s32(b[3], 19),
            vmul_n_s32(b[4], 19),
            vmul_n_s32(b[5], 19),
            vmul_n_s32(b[6], 19),
            vmul_n_s32(b[7], 19),
            vmul_n_s32(b[8], 19),
            vmul_n_s32(b[9], 19),
        ]
    };

    // 38 · b[i] for odd-odd wraparound.
    let b1_38 = unsafe { vmul_n_s32(b[1], 38) };
    let b3_38 = unsafe { vmul_n_s32(b[3], 38) };
    let b5_38 = unsafe { vmul_n_s32(b[5], 38) };
    let b7_38 = unsafe { vmul_n_s32(b[7], 38) };
    let b9_38 = unsafe { vmul_n_s32(b[9], 38) };

    // 2 · a[i] for odd-parity within in-range cross-products.
    let a1_2 = unsafe { vshl_n_s32::<1>(a[1]) };
    let a3_2 = unsafe { vshl_n_s32::<1>(a[3]) };
    let a5_2 = unsafe { vshl_n_s32::<1>(a[5]) };
    let a7_2 = unsafe { vshl_n_s32::<1>(a[7]) };

    // Compute each t_k as int64x2_t accumulator. The schedule mirrors
    // `super::mul::fmul` (see comments there for the (i,j) parity rules).
    // SAFETY: all NEON intrinsics on aarch64-cfg-gated module.
    let t = unsafe {
        // t0
        let t0 = vmull_s32(a[0], b[0]);
        let t0 = vmlal_s32(t0, a1_2, b_19[9]);
        let t0 = vmlal_s32(t0, a[2], b_19[8]);
        let t0 = vmlal_s32(t0, a3_2, b_19[7]);
        let t0 = vmlal_s32(t0, a[4], b_19[6]);
        let t0 = vmlal_s32(t0, a5_2, b_19[5]);
        let t0 = vmlal_s32(t0, a[6], b_19[4]);
        let t0 = vmlal_s32(t0, a7_2, b_19[3]);
        let t0 = vmlal_s32(t0, a[8], b_19[2]);
        let t0 = vmlal_s32(t0, a[9], b1_38);

        // t1
        let t1 = vmull_s32(a[0], b[1]);
        let t1 = vmlal_s32(t1, a[1], b[0]);
        let t1 = vmlal_s32(t1, a[2], b_19[9]);
        let t1 = vmlal_s32(t1, a[3], b_19[8]);
        let t1 = vmlal_s32(t1, a[4], b_19[7]);
        let t1 = vmlal_s32(t1, a[5], b_19[6]);
        let t1 = vmlal_s32(t1, a[6], b_19[5]);
        let t1 = vmlal_s32(t1, a[7], b_19[4]);
        let t1 = vmlal_s32(t1, a[8], b_19[3]);
        let t1 = vmlal_s32(t1, a[9], b_19[2]);

        // t2
        let t2 = vmull_s32(a[0], b[2]);
        let t2 = vmlal_s32(t2, a1_2, b[1]);
        let t2 = vmlal_s32(t2, a[2], b[0]);
        let t2 = vmlal_s32(t2, a3_2, b_19[9]);
        let t2 = vmlal_s32(t2, a[4], b_19[8]);
        let t2 = vmlal_s32(t2, a5_2, b_19[7]);
        let t2 = vmlal_s32(t2, a[6], b_19[6]);
        let t2 = vmlal_s32(t2, a7_2, b_19[5]);
        let t2 = vmlal_s32(t2, a[8], b_19[4]);
        let t2 = vmlal_s32(t2, a[9], b3_38);

        // t3
        let t3 = vmull_s32(a[0], b[3]);
        let t3 = vmlal_s32(t3, a[1], b[2]);
        let t3 = vmlal_s32(t3, a[2], b[1]);
        let t3 = vmlal_s32(t3, a[3], b[0]);
        let t3 = vmlal_s32(t3, a[4], b_19[9]);
        let t3 = vmlal_s32(t3, a[5], b_19[8]);
        let t3 = vmlal_s32(t3, a[6], b_19[7]);
        let t3 = vmlal_s32(t3, a[7], b_19[6]);
        let t3 = vmlal_s32(t3, a[8], b_19[5]);
        let t3 = vmlal_s32(t3, a[9], b_19[4]);

        // t4
        let t4 = vmull_s32(a[0], b[4]);
        let t4 = vmlal_s32(t4, a1_2, b[3]);
        let t4 = vmlal_s32(t4, a[2], b[2]);
        let t4 = vmlal_s32(t4, a3_2, b[1]);
        let t4 = vmlal_s32(t4, a[4], b[0]);
        let t4 = vmlal_s32(t4, a5_2, b_19[9]);
        let t4 = vmlal_s32(t4, a[6], b_19[8]);
        let t4 = vmlal_s32(t4, a7_2, b_19[7]);
        let t4 = vmlal_s32(t4, a[8], b_19[6]);
        let t4 = vmlal_s32(t4, a[9], b5_38);

        // t5
        let t5 = vmull_s32(a[0], b[5]);
        let t5 = vmlal_s32(t5, a[1], b[4]);
        let t5 = vmlal_s32(t5, a[2], b[3]);
        let t5 = vmlal_s32(t5, a[3], b[2]);
        let t5 = vmlal_s32(t5, a[4], b[1]);
        let t5 = vmlal_s32(t5, a[5], b[0]);
        let t5 = vmlal_s32(t5, a[6], b_19[9]);
        let t5 = vmlal_s32(t5, a[7], b_19[8]);
        let t5 = vmlal_s32(t5, a[8], b_19[7]);
        let t5 = vmlal_s32(t5, a[9], b_19[6]);

        // t6
        let t6 = vmull_s32(a[0], b[6]);
        let t6 = vmlal_s32(t6, a1_2, b[5]);
        let t6 = vmlal_s32(t6, a[2], b[4]);
        let t6 = vmlal_s32(t6, a3_2, b[3]);
        let t6 = vmlal_s32(t6, a[4], b[2]);
        let t6 = vmlal_s32(t6, a5_2, b[1]);
        let t6 = vmlal_s32(t6, a[6], b[0]);
        let t6 = vmlal_s32(t6, a7_2, b_19[9]);
        let t6 = vmlal_s32(t6, a[8], b_19[8]);
        let t6 = vmlal_s32(t6, a[9], b7_38);

        // t7
        let t7 = vmull_s32(a[0], b[7]);
        let t7 = vmlal_s32(t7, a[1], b[6]);
        let t7 = vmlal_s32(t7, a[2], b[5]);
        let t7 = vmlal_s32(t7, a[3], b[4]);
        let t7 = vmlal_s32(t7, a[4], b[3]);
        let t7 = vmlal_s32(t7, a[5], b[2]);
        let t7 = vmlal_s32(t7, a[6], b[1]);
        let t7 = vmlal_s32(t7, a[7], b[0]);
        let t7 = vmlal_s32(t7, a[8], b_19[9]);
        let t7 = vmlal_s32(t7, a[9], b_19[8]);

        // t8
        let t8 = vmull_s32(a[0], b[8]);
        let t8 = vmlal_s32(t8, a1_2, b[7]);
        let t8 = vmlal_s32(t8, a[2], b[6]);
        let t8 = vmlal_s32(t8, a3_2, b[5]);
        let t8 = vmlal_s32(t8, a[4], b[4]);
        let t8 = vmlal_s32(t8, a5_2, b[3]);
        let t8 = vmlal_s32(t8, a[6], b[2]);
        let t8 = vmlal_s32(t8, a7_2, b[1]);
        let t8 = vmlal_s32(t8, a[8], b[0]);
        let t8 = vmlal_s32(t8, a[9], b9_38);

        // t9
        let t9 = vmull_s32(a[0], b[9]);
        let t9 = vmlal_s32(t9, a[1], b[8]);
        let t9 = vmlal_s32(t9, a[2], b[7]);
        let t9 = vmlal_s32(t9, a[3], b[6]);
        let t9 = vmlal_s32(t9, a[4], b[5]);
        let t9 = vmlal_s32(t9, a[5], b[4]);
        let t9 = vmlal_s32(t9, a[6], b[3]);
        let t9 = vmlal_s32(t9, a[7], b[2]);
        let t9 = vmlal_s32(t9, a[8], b[1]);
        let t9 = vmlal_s32(t9, a[9], b[0]);

        [t0, t1, t2, t3, t4, t5, t6, t7, t8, t9]
    };

    // Carry chain in NEON int64x2_t. Two full passes ensure all limbs land
    // in their 25/26-bit windows, modulo a final 19-wrap at the top.
    // SAFETY: aarch64-only.
    let out = unsafe {
        let mask26 = vdupq_n_s64((1 << 26) - 1);
        let mask25 = vdupq_n_s64((1 << 25) - 1);

        let mut t = t;

        // pass 1
        let mut c;
        c = vshrq_n_s64::<26>(t[0]);
        t[0] = vandq_s64(t[0], mask26);
        t[1] = vaddq_s64(t[1], c);
        c = vshrq_n_s64::<25>(t[1]);
        t[1] = vandq_s64(t[1], mask25);
        t[2] = vaddq_s64(t[2], c);
        c = vshrq_n_s64::<26>(t[2]);
        t[2] = vandq_s64(t[2], mask26);
        t[3] = vaddq_s64(t[3], c);
        c = vshrq_n_s64::<25>(t[3]);
        t[3] = vandq_s64(t[3], mask25);
        t[4] = vaddq_s64(t[4], c);
        c = vshrq_n_s64::<26>(t[4]);
        t[4] = vandq_s64(t[4], mask26);
        t[5] = vaddq_s64(t[5], c);
        c = vshrq_n_s64::<25>(t[5]);
        t[5] = vandq_s64(t[5], mask25);
        t[6] = vaddq_s64(t[6], c);
        c = vshrq_n_s64::<26>(t[6]);
        t[6] = vandq_s64(t[6], mask26);
        t[7] = vaddq_s64(t[7], c);
        c = vshrq_n_s64::<25>(t[7]);
        t[7] = vandq_s64(t[7], mask25);
        t[8] = vaddq_s64(t[8], c);
        c = vshrq_n_s64::<26>(t[8]);
        t[8] = vandq_s64(t[8], mask26);
        t[9] = vaddq_s64(t[9], c);
        c = vshrq_n_s64::<25>(t[9]);
        t[9] = vandq_s64(t[9], mask25);
        // top wrap: t[0] += c * 19
        t[0] = vaddq_s64(t[0], vshlq_n_s64::<4>(c)); // c << 4 = 16c
        t[0] = vaddq_s64(t[0], vshlq_n_s64::<1>(c)); // + 2c
        t[0] = vaddq_s64(t[0], c); // + c — total 19c

        // pass 2 — handles any cascaded carry from the top wrap.
        c = vshrq_n_s64::<26>(t[0]);
        t[0] = vandq_s64(t[0], mask26);
        t[1] = vaddq_s64(t[1], c);
        c = vshrq_n_s64::<25>(t[1]);
        t[1] = vandq_s64(t[1], mask25);
        t[2] = vaddq_s64(t[2], c);
        c = vshrq_n_s64::<26>(t[2]);
        t[2] = vandq_s64(t[2], mask26);
        t[3] = vaddq_s64(t[3], c);
        c = vshrq_n_s64::<25>(t[3]);
        t[3] = vandq_s64(t[3], mask25);
        t[4] = vaddq_s64(t[4], c);
        c = vshrq_n_s64::<26>(t[4]);
        t[4] = vandq_s64(t[4], mask26);
        t[5] = vaddq_s64(t[5], c);
        c = vshrq_n_s64::<25>(t[5]);
        t[5] = vandq_s64(t[5], mask25);
        t[6] = vaddq_s64(t[6], c);
        c = vshrq_n_s64::<26>(t[6]);
        t[6] = vandq_s64(t[6], mask26);
        t[7] = vaddq_s64(t[7], c);
        c = vshrq_n_s64::<25>(t[7]);
        t[7] = vandq_s64(t[7], mask25);
        t[8] = vaddq_s64(t[8], c);
        c = vshrq_n_s64::<26>(t[8]);
        t[8] = vandq_s64(t[8], mask26);
        t[9] = vaddq_s64(t[9], c);

        t
    };

    // Unpack int64x2_t lanes back into (Fe2255, Fe2255).
    // SAFETY: aarch64-only lane-extract intrinsics.
    let mut out1 = [0i32; 10];
    let mut out2 = [0i32; 10];
    for (i, v) in out.iter().enumerate() {
        // SAFETY: vgetq_lane_s64 with const-generic lane index 0/1.
        unsafe {
            out1[i] = vgetq_lane_s64::<0>(*v) as i32;
            out2[i] = vgetq_lane_s64::<1>(*v) as i32;
        }
    }
    (out1, out2)
}
