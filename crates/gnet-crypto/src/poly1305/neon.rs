//! Four-lane NEON Poly1305 bulk evaluation (aarch64; NEON is baseline, so no
//! runtime detection).
//!
//! Same r-power decomposition as the AVX2 path —
//! `acc = (acc + n0)·r^4 + n1·r^3 + n2·r^2 + n3·r` — but a NEON register holds
//! only two 64-bit lanes, so the four independent multiplies span two
//! registers: the `lo` pair carries `(acc+n0)·r^4` and `n1·r^3`, the `hi` pair
//! `n2·r^2` and `n3·r`. Each 26-bit limb product is a `vmull_u32` (32×32→64,
//! exact for 26-bit inputs); the five product columns are summed across all
//! four lanes once per group, then reduced by the shared scalar
//! [`reduce_products`](super::reduce_products) — identical arithmetic to the
//! per-block path, which the differential test pins together.

use core::arch::aarch64::{
    uint32x2_t, uint64x2_t, vaddq_u64, vcreate_u32, vgetq_lane_u64, vmull_u32,
};

use super::{MASK, fmul5, load_le32, mul5, reduce_products};

/// Pack two 32-bit limbs into a NEON lane pair: lane 0 = `x`, lane 1 = `y`.
#[inline]
fn mk(x: u64, y: u64) -> uint32x2_t {
    // SAFETY: NEON is baseline on aarch64; vcreate is a pure register move.
    unsafe { vcreate_u32(x | (y << 32)) }
}

/// Read a full 16-byte block into five 26-bit limbs with the implicit 2^128
/// bit set (full-block path only — the partial tail block uses the scalar
/// state).
#[inline]
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

/// One product column `va[0]·b0 + va[1]·b1 + va[2]·b2 + va[3]·b3 + va[4]·b4`
/// over a lane pair (each lane its own operand/power).
#[inline]
fn col(
    va: &[uint32x2_t; 5],
    b0: uint32x2_t,
    b1: uint32x2_t,
    b2: uint32x2_t,
    b3: uint32x2_t,
    b4: uint32x2_t,
) -> uint64x2_t {
    // SAFETY: NEON is baseline on aarch64; pure lane-wise multiply/add.
    unsafe {
        let p0 = vmull_u32(va[0], b0);
        let p1 = vmull_u32(va[1], b1);
        let p2 = vmull_u32(va[2], b2);
        let p3 = vmull_u32(va[3], b3);
        let p4 = vmull_u32(va[4], b4);
        vaddq_u64(vaddq_u64(vaddq_u64(p0, p1), vaddq_u64(p2, p3)), p4)
    }
}

/// Sum the four lanes carried by the `lo` and `hi` halves of one column.
#[inline]
fn hsum(lo: uint64x2_t, hi: uint64x2_t) -> u64 {
    // SAFETY: NEON is baseline on aarch64; add + lane extracts.
    unsafe {
        let s = vaddq_u64(lo, hi);
        vgetq_lane_u64::<0>(s) + vgetq_lane_u64::<1>(s)
    }
}

/// Evaluate the four-block r-power path over whole 64-byte groups of `msg`
/// (its length must be a multiple of 64) starting from accumulator `init`,
/// returning the updated accumulator in five 26-bit limbs.
pub fn accumulate(r: &[u64; 5], init: [u64; 5], msg: &[u8]) -> [u64; 5] {
    // key powers, lane order lo = [r^4, r^3], hi = [r^2, r] — scalar arithmetic.
    let r2 = fmul5(r, r, &mul5(r));
    let r3 = fmul5(&r2, r, &mul5(r));
    let r4 = fmul5(&r2, &r2, &mul5(&r2));
    let (r4s, r3s, r2s, rs) = (mul5(&r4), mul5(&r3), mul5(&r2), mul5(r));

    let vb_lo: [uint32x2_t; 5] = core::array::from_fn(|k| mk(r4[k], r3[k]));
    let vb_hi: [uint32x2_t; 5] = core::array::from_fn(|k| mk(r2[k], r[k]));
    let vb5_lo: [uint32x2_t; 4] = core::array::from_fn(|j| mk(r4s[j], r3s[j]));
    let vb5_hi: [uint32x2_t; 4] = core::array::from_fn(|j| mk(r2s[j], rs[j]));

    let mut acc = init;
    for group in msg.chunks_exact(64) {
        let n0 = block_to_limbs(&group[0..16]);
        let n1 = block_to_limbs(&group[16..32]);
        let n2 = block_to_limbs(&group[32..48]);
        let n3 = block_to_limbs(&group[48..64]);
        // a-operands: lo lanes = acc+n0, n1; hi lanes = n2, n3.
        let va_lo: [uint32x2_t; 5] = core::array::from_fn(|k| mk(acc[k] + n0[k], n1[k]));
        let va_hi: [uint32x2_t; 5] = core::array::from_fn(|k| mk(n2[k], n3[k]));

        // product columns (mirrors super::products), summed across all lanes.
        let d0 = hsum(
            col(&va_lo, vb_lo[0], vb5_lo[3], vb5_lo[2], vb5_lo[1], vb5_lo[0]),
            col(&va_hi, vb_hi[0], vb5_hi[3], vb5_hi[2], vb5_hi[1], vb5_hi[0]),
        );
        let d1 = hsum(
            col(&va_lo, vb_lo[1], vb_lo[0], vb5_lo[3], vb5_lo[2], vb5_lo[1]),
            col(&va_hi, vb_hi[1], vb_hi[0], vb5_hi[3], vb5_hi[2], vb5_hi[1]),
        );
        let d2 = hsum(
            col(&va_lo, vb_lo[2], vb_lo[1], vb_lo[0], vb5_lo[3], vb5_lo[2]),
            col(&va_hi, vb_hi[2], vb_hi[1], vb_hi[0], vb5_hi[3], vb5_hi[2]),
        );
        let d3 = hsum(
            col(&va_lo, vb_lo[3], vb_lo[2], vb_lo[1], vb_lo[0], vb5_lo[3]),
            col(&va_hi, vb_hi[3], vb_hi[2], vb_hi[1], vb_hi[0], vb5_hi[3]),
        );
        let d4 = hsum(
            col(&va_lo, vb_lo[4], vb_lo[3], vb_lo[2], vb_lo[1], vb_lo[0]),
            col(&va_hi, vb_hi[4], vb_hi[3], vb_hi[2], vb_hi[1], vb_hi[0]),
        );

        acc = reduce_products([d0, d1, d2, d3, d4]);
    }
    acc
}
