//! GF(2^255 - 19) field arithmetic in five 51-bit limbs.
//!
//! Radix 2^51 representation with `u128` products, after the
//! curve25519-donna-c64 schedule. All ops are constant-time over the input
//! bit pattern (no secret-dependent branches) — `fmul` / `fsqr` carry chains
//! always run the same number of additions and shifts.

/// 51-bit field element (radix 2^51), five limbs.
pub(super) type Fe = [u64; 5];

pub(super) const MASK51: u64 = 0x0007_ffff_ffff_ffff;
pub(super) const TWO54M152: u64 = (1u64 << 54) - 152;
pub(super) const TWO54M8: u64 = (1u64 << 54) - 8;
pub(super) const FE_ZERO: Fe = [0; 5];
pub(super) const FE_ONE: Fe = [1, 0, 0, 0, 0];

pub(super) fn load_le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Field add (limbs grow; the next multiply re-reduces).
pub(super) const fn fadd(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

/// Field subtract `a - b`, biased by a multiple of `2p` to stay positive.
pub(super) const fn fsub(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + TWO54M152 - b[0],
        a[1] + TWO54M8 - b[1],
        a[2] + TWO54M8 - b[2],
        a[3] + TWO54M8 - b[3],
        a[4] + TWO54M8 - b[4],
    ]
}

/// Field multiply with 2^255-19 reduction (curve25519-donna-c64 schedule).
pub(super) const fn fmul(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3, r4) = (a[0], a[1], a[2], a[3], a[4]);
    let (s0, s1, s2, s3, s4) = (b[0], b[1], b[2], b[3], b[4]);

    let mut t0 = (r0 as u128) * (s0 as u128);
    let mut t1 = (r0 as u128) * (s1 as u128) + (r1 as u128) * (s0 as u128);
    let mut t2 =
        (r0 as u128) * (s2 as u128) + (r2 as u128) * (s0 as u128) + (r1 as u128) * (s1 as u128);
    let mut t3 = (r0 as u128) * (s3 as u128)
        + (r3 as u128) * (s0 as u128)
        + (r1 as u128) * (s2 as u128)
        + (r2 as u128) * (s1 as u128);
    let mut t4 = (r0 as u128) * (s4 as u128)
        + (r4 as u128) * (s0 as u128)
        + (r3 as u128) * (s1 as u128)
        + (r1 as u128) * (s3 as u128)
        + (r2 as u128) * (s2 as u128);

    let (e1, e2, e3, e4) = (r1 * 19, r2 * 19, r3 * 19, r4 * 19);
    t0 += (e4 as u128) * (s1 as u128)
        + (e1 as u128) * (s4 as u128)
        + (e2 as u128) * (s3 as u128)
        + (e3 as u128) * (s2 as u128);
    t1 += (e4 as u128) * (s2 as u128) + (e2 as u128) * (s4 as u128) + (e3 as u128) * (s3 as u128);
    t2 += (e4 as u128) * (s3 as u128) + (e3 as u128) * (s4 as u128);
    t3 += (e4 as u128) * (s4 as u128);

    let mut o0 = (t0 as u64) & MASK51;
    let mut c = (t0 >> 51) as u64;
    t1 += c as u128;
    let mut o1 = (t1 as u64) & MASK51;
    c = (t1 >> 51) as u64;
    t2 += c as u128;
    let mut o2 = (t2 as u64) & MASK51;
    c = (t2 >> 51) as u64;
    t3 += c as u128;
    let o3 = (t3 as u64) & MASK51;
    c = (t3 >> 51) as u64;
    t4 += c as u128;
    let o4 = (t4 as u64) & MASK51;
    c = (t4 >> 51) as u64;
    o0 += c * 19;
    c = o0 >> 51;
    o0 &= MASK51;
    o1 += c;
    c = o1 >> 51;
    o1 &= MASK51;
    o2 += c;
    [o0, o1, o2, o3, o4]
}

/// Field square (curve25519-donna-c64 schedule). Faster than `fmul(a, a)`:
/// the off-diagonal cross terms are computed once and doubled.
pub(super) const fn fsqr(a: &Fe) -> Fe {
    let (r0, r1, r2, r3, r4) = (a[0], a[1], a[2], a[3], a[4]);
    let d0 = r0 * 2;
    let d1 = r1 * 2;
    let d2 = r2 * 2 * 19;
    let d419 = r4 * 19;
    let d4 = d419 * 2;

    let t0 =
        (r0 as u128) * (r0 as u128) + (d4 as u128) * (r1 as u128) + (d2 as u128) * (r3 as u128);
    let mut t1 = (d0 as u128) * (r1 as u128)
        + (d4 as u128) * (r2 as u128)
        + (r3 as u128) * ((r3 * 19) as u128);
    let mut t2 =
        (d0 as u128) * (r2 as u128) + (r1 as u128) * (r1 as u128) + (d4 as u128) * (r3 as u128);
    let mut t3 =
        (d0 as u128) * (r3 as u128) + (d1 as u128) * (r2 as u128) + (r4 as u128) * (d419 as u128);
    let mut t4 =
        (d0 as u128) * (r4 as u128) + (d1 as u128) * (r3 as u128) + (r2 as u128) * (r2 as u128);

    let mut o0 = (t0 as u64) & MASK51;
    let mut c = (t0 >> 51) as u64;
    t1 += c as u128;
    let mut o1 = (t1 as u64) & MASK51;
    c = (t1 >> 51) as u64;
    t2 += c as u128;
    let mut o2 = (t2 as u64) & MASK51;
    c = (t2 >> 51) as u64;
    t3 += c as u128;
    let o3 = (t3 as u64) & MASK51;
    c = (t3 >> 51) as u64;
    t4 += c as u128;
    let o4 = (t4 as u64) & MASK51;
    c = (t4 >> 51) as u64;
    o0 += c * 19;
    c = o0 >> 51;
    o0 &= MASK51;
    o1 += c;
    c = o1 >> 51;
    o1 &= MASK51;
    o2 += c;
    [o0, o1, o2, o3, o4]
}

/// Repeated squaring: `a^(2^n)`.
pub(super) const fn fsqr_n(mut a: Fe, n: usize) -> Fe {
    let mut i = 0;
    while i < n {
        a = fsqr(&a);
        i += 1;
    }
    a
}

/// Field multiply by the small constant 121665 (= a24).
pub(super) fn fmul121665(a: &Fe) -> Fe {
    let s = 121665u128;
    let mut acc = u128::from(a[0]) * s;
    let o0 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[1]) * s;
    let o1 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[2]) * s;
    let o2 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[3]) * s;
    let o3 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[4]) * s;
    let o4 = (acc as u64) & MASK51;
    acc >>= 51;
    [o0 + (acc as u64) * 19, o1, o2, o3, o4]
}

/// Single-pass carry propagation that brings any limb vector with limbs
/// up to ~2^60 down to a tight form (limbs ≤ 2^51 + small). Used by the
/// Edwards code to keep chained `fsub` / `fadd` results inside `fmul`'s
/// safe input range — `fmul`'s schedule assumes limbs ≤ ~2^53, which
/// repeated additive ops can exceed (e.g. two stacked `fsub` calls each
/// bias limb 0 by `TWO54M152 ≈ 2^54`).
pub(super) const fn reduce_loose(a: &Fe) -> Fe {
    let mut t = *a;
    t[1] += t[0] >> 51;
    t[0] &= MASK51;
    t[2] += t[1] >> 51;
    t[1] &= MASK51;
    t[3] += t[2] >> 51;
    t[2] &= MASK51;
    t[4] += t[3] >> 51;
    t[3] &= MASK51;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK51;
    // second pass for the wraparound carry into limb 0
    t[1] += t[0] >> 51;
    t[0] &= MASK51;
    t
}

/// Constant-time conditional swap of `a` and `b` when `swap` is 1.
pub(super) fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap & 1);
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Field inverse `z^(p-2)` via Fermat (curve25519-donna addition chain).
pub(super) const fn finvert(z: &Fe) -> Fe {
    let z2 = fsqr(z);
    let z8 = fsqr_n(z2, 2);
    let z9 = fmul(&z8, z);
    let z11 = fmul(&z9, &z2);
    let z22 = fsqr(&z11);
    let z2_5_0 = fmul(&z22, &z9);
    let z2_10_0 = fmul(&fsqr_n(z2_5_0, 5), &z2_5_0);
    let z2_20_0 = fmul(&fsqr_n(z2_10_0, 10), &z2_10_0);
    let z2_40_0 = fmul(&fsqr_n(z2_20_0, 20), &z2_20_0);
    let z2_50_0 = fmul(&fsqr_n(z2_40_0, 10), &z2_10_0);
    let z2_100_0 = fmul(&fsqr_n(z2_50_0, 50), &z2_50_0);
    let z2_200_0 = fmul(&fsqr_n(z2_100_0, 100), &z2_100_0);
    let z2_250_0 = fmul(&fsqr_n(z2_200_0, 50), &z2_50_0);
    fmul(&fsqr_n(z2_250_0, 5), &z11)
}

/// Decode a u-coordinate (RFC 7748): little-endian, high bit masked.
pub(super) fn unpack(b: &[u8; 32]) -> Fe {
    [
        load_le64(&b[0..8]) & MASK51,
        (load_le64(&b[6..14]) >> 3) & MASK51,
        (load_le64(&b[12..20]) >> 6) & MASK51,
        (load_le64(&b[19..27]) >> 1) & MASK51,
        (load_le64(&b[24..32]) >> 12) & MASK51,
    ]
}

/// Reduce fully mod p and serialize to 32 little-endian bytes.
pub(super) fn pack(input: &Fe) -> [u8; 32] {
    let mut t = *input;
    for _ in 0..2 {
        t[1] += t[0] >> 51;
        t[0] &= MASK51;
        t[2] += t[1] >> 51;
        t[1] &= MASK51;
        t[3] += t[2] >> 51;
        t[2] &= MASK51;
        t[4] += t[3] >> 51;
        t[3] &= MASK51;
        t[0] += 19 * (t[4] >> 51);
        t[4] &= MASK51;
    }
    // add 19, carry: now offset so a conditional subtraction of p is exact
    t[0] += 19;
    t[1] += t[0] >> 51;
    t[0] &= MASK51;
    t[2] += t[1] >> 51;
    t[1] &= MASK51;
    t[3] += t[2] >> 51;
    t[2] &= MASK51;
    t[4] += t[3] >> 51;
    t[3] &= MASK51;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK51;
    // add 2^255 - 19, carry, drop the top bit
    t[0] += (1u64 << 51) - 19;
    t[1] += (1u64 << 51) - 1;
    t[2] += (1u64 << 51) - 1;
    t[3] += (1u64 << 51) - 1;
    t[4] += (1u64 << 51) - 1;
    t[1] += t[0] >> 51;
    t[0] &= MASK51;
    t[2] += t[1] >> 51;
    t[1] &= MASK51;
    t[3] += t[2] >> 51;
    t[2] &= MASK51;
    t[4] += t[3] >> 51;
    t[3] &= MASK51;
    t[4] &= MASK51;

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&(t[0] | (t[1] << 51)).to_le_bytes());
    out[8..16].copy_from_slice(&((t[1] >> 13) | (t[2] << 38)).to_le_bytes());
    out[16..24].copy_from_slice(&((t[2] >> 26) | (t[3] << 25)).to_le_bytes());
    out[24..32].copy_from_slice(&((t[3] >> 39) | (t[4] << 12)).to_le_bytes());
    out
}
