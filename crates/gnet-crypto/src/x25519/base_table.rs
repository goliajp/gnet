//! Compile-time precomputed comb table for the Ed25519 basepoint.
//!
//! Layout: 64 four-bit windows, 8 cached multiples per window. Entry
//! `TABLE[i][j]` holds the cached form of `(j + 1) · 16^i · B`. A
//! 4-bit signed-digit recoded scalar (`d_i ∈ {-8, …, 8}`) drives one
//! constant-time `ct_select_cached` + conditional negate + `mixed_add`
//! per window, replacing the 256-iteration Montgomery ladder for the
//! fixed-base case.
//!
//! Storage: 64 × 8 = 512 `CachedPoint`s; each cached point is three
//! 5-limb `Fe`s = 120 bytes. Total `.rodata` ≈ 60 KiB.

use super::edwards::{
    BASEPOINT, CachedPoint, IDENTITY_CACHED, ed_add, ed_double, normalize, to_cached_affine,
};

/// Number of 4-bit windows in a 256-bit scalar.
pub(super) const WINDOWS: usize = 64;

/// Entries per window: the `j`-th entry holds `(j + 1) · 16^i · B`,
/// `j ∈ {0, …, 7}`. The recoded digit `0` corresponds to the cached
/// identity element and is handled outside the table.
pub(super) const ENTRIES: usize = 8;

const fn build_table() -> [[CachedPoint; ENTRIES]; WINDOWS] {
    let mut table = [[IDENTITY_CACHED; ENTRIES]; WINDOWS];
    let mut window_base = BASEPOINT;
    let mut i = 0;
    while i < WINDOWS {
        let mut multiple = window_base;
        let mut j = 0;
        while j < ENTRIES {
            let aff = normalize(&multiple);
            table[i][j] = to_cached_affine(&aff);
            j += 1;
            if j < ENTRIES {
                multiple = ed_add(&multiple, &window_base);
            }
        }
        // Advance the window base: window_base ← 16 · window_base.
        if i + 1 < WINDOWS {
            let d1 = ed_double(&window_base);
            let d2 = ed_double(&d1);
            let d3 = ed_double(&d2);
            window_base = ed_double(&d3);
        }
        i += 1;
    }
    table
}

pub(super) static TABLE: [[CachedPoint; ENTRIES]; WINDOWS] = build_table();

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::edwards::{
        ct_select_cached, ed_mixed_add, ed_to_mont_u, IDENTITY,
    };

    #[test]
    fn table_window_0_first_entry_is_basepoint_cached() {
        // TABLE[0][0] = 1 · 16^0 · B = BASEPOINT (cached).
        let expected = to_cached_affine(&BASEPOINT);
        assert_eq!(TABLE[0][0].y_minus_x, expected.y_minus_x);
        assert_eq!(TABLE[0][0].y_plus_x, expected.y_plus_x);
        assert_eq!(TABLE[0][0].t2d, expected.t2d);
    }

    #[test]
    fn table_window_0_second_entry_is_double_basepoint() {
        // TABLE[0][1] = 2 · 16^0 · B = 2·B (cached).
        let two_b = normalize(&ed_double(&BASEPOINT));
        let expected = to_cached_affine(&two_b);
        assert_eq!(TABLE[0][1].y_minus_x, expected.y_minus_x);
        assert_eq!(TABLE[0][1].y_plus_x, expected.y_plus_x);
        assert_eq!(TABLE[0][1].t2d, expected.t2d);
    }

    #[test]
    fn table_window_advances_by_16x() {
        // TABLE[1][0] = 1 · 16^1 · B = 16·B. Compute reference via four
        // doublings of the basepoint.
        let sixteen_b =
            normalize(&ed_double(&ed_double(&ed_double(&ed_double(&BASEPOINT)))));
        let expected = to_cached_affine(&sixteen_b);
        assert_eq!(TABLE[1][0].y_minus_x, expected.y_minus_x);
        assert_eq!(TABLE[1][0].y_plus_x, expected.y_plus_x);
        assert_eq!(TABLE[1][0].t2d, expected.t2d);
    }

    #[test]
    fn signed_recoding_combs_to_basepoint_for_small_scalar() {
        // Build scalar = 17 = 1 · 16^0 + 1 · 16^1, i.e. nibbles [1, 1, 0, ..., 0].
        // Expected: result = (1·B) + (1·16·B) = 17·B on the Edwards curve.
        // Then ed_to_mont_u(result) should match Montgomery ladder of clamped(17).
        let mut acc = IDENTITY;
        // d_0 = 1 → table[0][0] = 1·B
        let p0 = ct_select_cached(&TABLE[0], 1);
        acc = ed_mixed_add(&acc, &p0);
        // d_1 = 1 → table[1][0] = 16·B
        let p1 = ct_select_cached(&TABLE[1], 1);
        acc = ed_mixed_add(&acc, &p1);
        let u = ed_to_mont_u(&acc);

        // Reference: compute 17·B via repeated doubling on the Edwards side.
        let mut ref_acc = BASEPOINT;
        let mut k = 0;
        while k < 16 {
            ref_acc = ed_add(&ref_acc, &BASEPOINT);
            k += 1;
        }
        let ref_u = ed_to_mont_u(&ref_acc);
        assert_eq!(u, ref_u);
    }
}
