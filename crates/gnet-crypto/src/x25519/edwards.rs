//! Ed25519 / Curve25519 birational map: Edwards-curve operations on the
//! same 51-bit GF(2^255 - 19) field as [`super::scalar`], used by
//! [`super::base`] to accelerate fixed-base X25519 (`x25519_base`).
//!
//! Twisted Edwards form, `-x² + y² = 1 + d·x²·y²` with
//! `d = -121665 / 121666 (mod p)`. Extended coordinates `(X, Y, Z, T)` with
//! `T = XY/Z`. Add / double use the unified Hisil-Wong-Carter-Dawson 2008
//! formulas; the mixed-add (with one operand pre-cached as
//! `(Y-X, Y+X, T·2d)`) costs 7 field multiplications.
//!
//! Constant-time table select and conditional negate are mask-driven so the
//! caller can do a fixed-base scalar multiplication without leaking any
//! scalar bits through timing or branches.

use super::field::{Fe, FE_ONE, FE_ZERO, MASK51, fadd, finvert, fmul, fsqr, fsub, reduce_loose};

/// Extended-coordinate Edwards point `(X, Y, Z, T)` with `T = XY/Z`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Point {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) z: Fe,
    pub(super) t: Fe,
}

/// Cached representation `(Y-X, Y+X, T·2d)` consumed by [`ed_mixed_add`].
/// Each entry of `super::base_table` is stored cached so the comb loop
/// spends 7 field multiplications per windowed add instead of 9.
#[derive(Clone, Copy, Debug)]
pub(super) struct CachedPoint {
    pub(super) y_minus_x: Fe,
    pub(super) y_plus_x: Fe,
    pub(super) t2d: Fe,
}

/// Identity element of the Edwards group: `(0, 1, 1, 0)`.
pub(super) const IDENTITY: Point = Point {
    x: FE_ZERO,
    y: FE_ONE,
    z: FE_ONE,
    t: FE_ZERO,
};

/// Cached identity: `(1, 1, 0)`. Used by [`ct_select_cached`] when the
/// scalar digit is zero.
pub(super) const IDENTITY_CACHED: CachedPoint = CachedPoint {
    y_minus_x: FE_ONE,
    y_plus_x: FE_ONE,
    t2d: FE_ZERO,
};

/// Curve constant `d = -121665 / 121666 (mod p)`. Computed at compile time
/// from the small integer numerator / denominator; verified by the
/// `basepoint_satisfies_curve` test below.
pub(super) const D: Fe = {
    let num: Fe = [121665, 0, 0, 0, 0];
    let den: Fe = [121666, 0, 0, 0, 0];
    let abs_d = fmul(&num, &finvert(&den));
    // d = -abs_d mod p. The non-reduced representative from fsub is fine
    // — the next fmul re-reduces.
    fsub(&FE_ZERO, &abs_d)
};

/// `2·d (mod p)` — the constant baked into every cached point's `t2d`.
pub(super) const D2: Fe = {
    let mut out = [0u64; 5];
    let mut i = 0;
    while i < 5 {
        out[i] = D[i] + D[i];
        i += 1;
    }
    out
};

/// Decode 32 little-endian bytes into a 51-bit-limb field element.
/// Identical layout to [`super::field::unpack`] but `const fn`.
const fn unpack_le_const(b: &[u8; 32]) -> Fe {
    let l0 = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) & MASK51;
    let l1 = (u64::from_le_bytes([b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13]]) >> 3)
        & MASK51;
    let l2 = (u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]) >> 6)
        & MASK51;
    let l3 = (u64::from_le_bytes([b[19], b[20], b[21], b[22], b[23], b[24], b[25], b[26]]) >> 1)
        & MASK51;
    let l4 = (u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]) >> 12)
        & MASK51;
    [l0, l1, l2, l3, l4]
}

/// Ed25519 basepoint in extended coords.
///
/// `Y = 4/5 (mod p)` — computed at compile time. `X` is the canonical
/// parity-0 root of the curve equation at this `Y`, taken from RFC 8032
/// §5.1 in its little-endian byte form. The `basepoint_satisfies_curve`
/// KAT below verifies that the hard-coded `X` decodes correctly.
pub(super) const BASEPOINT: Point = {
    let four: Fe = [4, 0, 0, 0, 0];
    let five: Fe = [5, 0, 0, 0, 0];
    let y = fmul(&four, &finvert(&five));

    // RFC 8032 §5.1 — Ed25519 basepoint X (parity 0), little-endian.
    let x_bytes: [u8; 32] = [
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
        0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
        0xd3, 0x36, 0x69, 0x21,
    ];
    let x = unpack_le_const(&x_bytes);

    let t = fmul(&x, &y);

    Point { x, y, z: FE_ONE, t }
};

/// Twisted-Edwards add, extended coords (HWCD 2008). 9 fmul total.
///
/// `reduce_loose` is called on every `fsub` chain that feeds back into
/// `fmul` so the limbs stay within the safe input range. `const` so the
/// base table in [`super::base_table`] can be built at compile time.
pub(super) const fn ed_add(p: &Point, q: &Point) -> Point {
    let py_minus_px = reduce_loose(&fsub(&p.y, &p.x));
    let qy_minus_qx = reduce_loose(&fsub(&q.y, &q.x));
    let a = fmul(&py_minus_px, &qy_minus_qx);
    let b = fmul(&fadd(&p.y, &p.x), &fadd(&q.y, &q.x));
    let c = fmul(&fmul(&p.t, &D2), &q.t);
    let d = fmul(&p.z, &fadd(&q.z, &q.z));
    let e = reduce_loose(&fsub(&b, &a));
    let f = reduce_loose(&fsub(&d, &c));
    let g = fadd(&d, &c);
    let h = fadd(&b, &a);
    Point {
        x: fmul(&e, &f),
        y: fmul(&g, &h),
        z: fmul(&f, &g),
        t: fmul(&e, &h),
    }
}

/// Twisted-Edwards mixed add: `p` extended, `q` cached. 7 fmul total —
/// the hot path inside the fixed-base comb loop.
pub(super) fn ed_mixed_add(p: &Point, q: &CachedPoint) -> Point {
    let a = fmul(&reduce_loose(&fsub(&p.y, &p.x)), &q.y_minus_x);
    let b = fmul(&fadd(&p.y, &p.x), &q.y_plus_x);
    let c = fmul(&p.t, &q.t2d);
    let d = fadd(&p.z, &p.z);
    let e = reduce_loose(&fsub(&b, &a));
    let f = reduce_loose(&fsub(&d, &c));
    let g = fadd(&d, &c);
    let h = fadd(&b, &a);
    Point {
        x: fmul(&e, &f),
        y: fmul(&g, &h),
        z: fmul(&f, &g),
        t: fmul(&e, &h),
    }
}

/// Edwards double, extended coords (HWCD 2008). Uses `a = -1` for Ed25519.
/// 4 fsqr + 4 fmul. `const` so [`super::base_table`] can use it for the
/// 16× window step at compile time.
pub(super) const fn ed_double(p: &Point) -> Point {
    let a = fsqr(&p.x);
    let b = fsqr(&p.y);
    let c = fadd(&fsqr(&p.z), &fsqr(&p.z));
    let neg_a = reduce_loose(&fsub(&FE_ZERO, &a));
    let xy = fadd(&p.x, &p.y);
    let xy_sq = fsqr(&xy);
    let e = reduce_loose(&fsub(&fsub(&xy_sq, &a), &b));
    let g = fadd(&neg_a, &b);
    let f = reduce_loose(&fsub(&g, &c));
    let h = reduce_loose(&fsub(&neg_a, &b));
    Point {
        x: fmul(&e, &f),
        y: fmul(&g, &h),
        z: fmul(&f, &g),
        t: fmul(&e, &h),
    }
}

/// Convert an affine point (Z = 1) to cached `(Y-X, Y+X, T·2d)` form.
/// `const` so the precomputed base table can be built at compile time.
pub(super) const fn to_cached_affine(p: &Point) -> CachedPoint {
    CachedPoint {
        y_minus_x: fsub(&p.y, &p.x),
        y_plus_x: fadd(&p.y, &p.x),
        t2d: fmul(&p.t, &D2),
    }
}

/// Normalize an extended-coord point to its affine representative
/// (Z = 1). `const` so it composes with [`to_cached_affine`] when the
/// base table is being populated.
pub(super) const fn normalize(p: &Point) -> Point {
    let z_inv = finvert(&p.z);
    let x = fmul(&p.x, &z_inv);
    let y = fmul(&p.y, &z_inv);
    let t = fmul(&x, &y);
    Point { x, y, z: FE_ONE, t }
}

/// Mask of all-ones when `a == b`, all-zeros otherwise. Constant time.
pub(super) fn ct_eq_u8(a: u8, b: u8) -> u64 {
    let diff = u64::from(a) ^ u64::from(b);
    // (diff | diff.wrapping_neg()) >> 63 → 0 if diff == 0 else 1
    let nonzero = (diff | diff.wrapping_neg()) >> 63;
    nonzero.wrapping_sub(1)
}

/// Constant-time select of one cached point from a fixed-size table.
///
/// Caller passes `abs_d ∈ {0, 1, ..., N}`. The table entries are
/// `[1·X, 2·X, ..., N·X]` for some `X = base^i · B` (with `base` = 16 at
/// width 4 or 32 at width 5). Result is the cached identity when
/// `abs_d == 0`; otherwise `table[abs_d - 1]`.
///
/// All `N` entries are touched on every call, with the chosen one
/// selected via mask XOR — no scalar-dependent branches, memory
/// accesses, or timing. Const-generic in `N` so width-4 (`N = 8`) and
/// width-5 (`N = 16`) comb implementations share the same hot loop body.
pub(super) fn ct_select_cached<const N: usize>(
    table_i: &[CachedPoint; N],
    abs_d: u8,
) -> CachedPoint {
    let mut out = IDENTITY_CACHED;
    for (j, src) in table_i.iter().enumerate() {
        let mask = ct_eq_u8(abs_d, (j + 1) as u8);
        for k in 0..5 {
            out.y_minus_x[k] ^= mask & (out.y_minus_x[k] ^ src.y_minus_x[k]);
            out.y_plus_x[k] ^= mask & (out.y_plus_x[k] ^ src.y_plus_x[k]);
            out.t2d[k] ^= mask & (out.t2d[k] ^ src.t2d[k]);
        }
    }
    out
}

/// Constant-time conditional negation: when `neg_mask == u64::MAX`,
/// swap `(Y-X) ↔ (Y+X)` and negate `t2d` (the cached form of `-P`).
/// When `neg_mask == 0`, leave the point unchanged. Branch-free.
pub(super) fn ct_negate_cached(p: &mut CachedPoint, neg_mask: u64) {
    for k in 0..5 {
        let t = neg_mask & (p.y_minus_x[k] ^ p.y_plus_x[k]);
        p.y_minus_x[k] ^= t;
        p.y_plus_x[k] ^= t;
    }
    let neg_t2d = fsub(&FE_ZERO, &p.t2d);
    for (t, &neg) in p.t2d.iter_mut().zip(neg_t2d.iter()) {
        *t ^= neg_mask & (*t ^ neg);
    }
}

/// Project an Edwards point back to a Curve25519 u-coordinate via the
/// birational map `u = (1 + y) / (1 - y)`. With `y = Y/Z` this is
/// `u = (Z + Y) / (Z - Y)`. Returns the 32-byte little-endian encoding.
pub(super) fn ed_to_mont_u(p: &Point) -> [u8; 32] {
    let zy_plus = fadd(&p.z, &p.y);
    let zy_minus = fsub(&p.z, &p.y);
    let u = fmul(&zy_plus, &finvert(&zy_minus));
    super::field::pack(&u)
}

/// Same as [`ed_to_mont_u`] applied to two points, but performs a single
/// shared [`finvert`] instead of one per point. Saves ≈ 2 µs on Apple
/// Silicon (one Curve25519 field inversion is the ~265-fmul addition
/// chain in [`super::field::finvert`]).
///
/// Algorithm — Montgomery's batch inversion trick:
/// ```text
///   prod      = (Z₁ - Y₁) · (Z₂ - Y₂)
///   prod_inv  = prod⁻¹                          (one finvert)
///   inv₁      = (Z₂ - Y₂) · prod_inv            (= (Z₁ - Y₁)⁻¹)
///   inv₂      = (Z₁ - Y₁) · prod_inv            (= (Z₂ - Y₂)⁻¹)
///   uᵢ        = (Zᵢ + Yᵢ) · invᵢ
/// ```
/// Net cost: 1 finvert + 5 fmul + 2 pack — vs 2 × (1 finvert + 1 fmul +
/// 1 pack) for two independent calls.
pub(super) fn ed_to_mont_u_pair(p1: &Point, p2: &Point) -> ([u8; 32], [u8; 32]) {
    let zy_p1 = fadd(&p1.z, &p1.y);
    let zy_m1 = fsub(&p1.z, &p1.y);
    let zy_p2 = fadd(&p2.z, &p2.y);
    let zy_m2 = fsub(&p2.z, &p2.y);

    // Batched inversion: one shared finvert across both denominators.
    let prod = fmul(&zy_m1, &zy_m2);
    let prod_inv = finvert(&prod);
    let zy_m1_inv = fmul(&zy_m2, &prod_inv);
    let zy_m2_inv = fmul(&zy_m1, &prod_inv);

    let u1 = fmul(&zy_p1, &zy_m1_inv);
    let u2 = fmul(&zy_p2, &zy_m2_inv);
    (super::field::pack(&u1), super::field::pack(&u2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field::pack;

    /// Variable-time double-and-add scalar mult for test only (do not use
    /// in prod — leaks scalar bits via branches).
    fn vt_scalar_mul(s: &[u8; 32], p: &Point) -> Point {
        let mut acc = IDENTITY;
        for bit in (0..=255).rev() {
            acc = ed_double(&acc);
            let bit_set = ((s[bit >> 3] >> (bit & 7)) & 1) != 0;
            if bit_set {
                acc = ed_add(&acc, p);
            }
        }
        acc
    }

    /// Reduce a possibly-unreduced Fe to its canonical packed form so that
    /// two field elements representing the same residue compare equal.
    fn canon(fe: &Fe) -> [u8; 32] {
        pack(fe)
    }

    #[test]
    fn basepoint_satisfies_curve() {
        // Verify -x² + y² == 1 + d·x²·y² (Ed25519 twisted-Edwards eq).
        let x2 = fsqr(&BASEPOINT.x);
        let y2 = fsqr(&BASEPOINT.y);
        let lhs = fadd(&fsub(&FE_ZERO, &x2), &y2);
        let dx2y2 = fmul(&D, &fmul(&x2, &y2));
        let rhs = fadd(&FE_ONE, &dx2y2);
        assert_eq!(canon(&lhs), canon(&rhs));
    }

    #[test]
    fn basepoint_t_consistent() {
        // T must equal X·Y (with Z = 1).
        let xy = fmul(&BASEPOINT.x, &BASEPOINT.y);
        assert_eq!(canon(&xy), canon(&BASEPOINT.t));
    }

    #[test]
    fn ed_add_self_matches_double() {
        // P + P (general add) must equal 2·P (specialized double).
        let twice_via_add = ed_add(&BASEPOINT, &BASEPOINT);
        let twice_via_dbl = ed_double(&BASEPOINT);
        // Compare projective coords by normalizing both.
        let a = normalize(&twice_via_add);
        let b = normalize(&twice_via_dbl);
        assert_eq!(canon(&a.x), canon(&b.x));
        assert_eq!(canon(&a.y), canon(&b.y));
    }

    #[test]
    fn ed_mixed_add_matches_general_add() {
        // Doubled basepoint as the "extended" operand.
        let p2 = ed_double(&BASEPOINT);
        let p2_via_mixed = ed_mixed_add(&p2, &to_cached_affine(&BASEPOINT));
        let p2_via_full = ed_add(&p2, &BASEPOINT);
        let a = normalize(&p2_via_mixed);
        let b = normalize(&p2_via_full);
        assert_eq!(canon(&a.x), canon(&b.x));
        assert_eq!(canon(&a.y), canon(&b.y));
    }

    #[test]
    fn ct_negate_cached_is_self_inverse() {
        let c = to_cached_affine(&BASEPOINT);
        let mut neg = c;
        ct_negate_cached(&mut neg, u64::MAX);
        // (Y-X) and (Y+X) should be swapped:
        assert_eq!(canon(&neg.y_minus_x), canon(&c.y_plus_x));
        assert_eq!(canon(&neg.y_plus_x), canon(&c.y_minus_x));
        // Negating again restores:
        ct_negate_cached(&mut neg, u64::MAX);
        assert_eq!(canon(&neg.y_minus_x), canon(&c.y_minus_x));
        assert_eq!(canon(&neg.y_plus_x), canon(&c.y_plus_x));
        assert_eq!(canon(&neg.t2d), canon(&c.t2d));
        // Zero mask is no-op:
        let mut nop = c;
        ct_negate_cached(&mut nop, 0);
        assert_eq!(canon(&nop.y_minus_x), canon(&c.y_minus_x));
        assert_eq!(canon(&nop.t2d), canon(&c.t2d));
    }

    #[test]
    fn ct_select_cached_picks_right_entry() {
        // Build a tiny table: [1·B, 2·B, ..., 8·B] cached.
        let mut acc = BASEPOINT;
        let mut table = [IDENTITY_CACHED; 8];
        for (j, entry) in table.iter_mut().enumerate() {
            let aff = if j == 0 { BASEPOINT } else { normalize(&acc) };
            *entry = to_cached_affine(&aff);
            acc = ed_add(&acc, &BASEPOINT);
        }
        // Selecting 0 → identity.
        let s0 = ct_select_cached(&table, 0);
        assert_eq!(canon(&s0.y_minus_x), canon(&IDENTITY_CACHED.y_minus_x));
        assert_eq!(canon(&s0.t2d), canon(&IDENTITY_CACHED.t2d));
        // Selecting j+1 → table[j].
        for j in 0..8u8 {
            let s = ct_select_cached(&table, j + 1);
            assert_eq!(canon(&s.y_minus_x), canon(&table[j as usize].y_minus_x));
            assert_eq!(canon(&s.y_plus_x), canon(&table[j as usize].y_plus_x));
            assert_eq!(canon(&s.t2d), canon(&table[j as usize].t2d));
        }
    }

    #[test]
    fn edwards_basepoint_matches_montgomery_for_known_vector() {
        // RFC 7748 §6.1 — Alice's secret key, clamped, scalar-multiplied
        // by the basepoint should yield her public key on the Montgomery
        // u-axis.
        let mut a_priv = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        a_priv[0] &= 248;
        a_priv[31] &= 127;
        a_priv[31] |= 64;
        let acc = vt_scalar_mul(&a_priv, &BASEPOINT);
        let u = ed_to_mont_u(&acc);
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(u, expected);
    }
}
