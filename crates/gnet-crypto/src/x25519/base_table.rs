//! Compile-time precomputed comb table for the Ed25519 basepoint.
//!
//! Layout: 52 five-bit windows, 16 cached multiples per window. Entry
//! `TABLE[i][j]` holds the cached form of `(j + 1) · 32^i · B`. A
//! 5-bit signed-digit recoded scalar (`d_i ∈ {-16, …, 16}`) drives one
//! constant-time `ct_select_cached` + conditional negate + `mixed_add`
//! per window, replacing the 256-iteration Montgomery ladder for the
//! fixed-base case.
//!
//! Why width 5 (and not 4):
//! - 256-bit scalar / 5 bits-per-window = 52 windows (vs 64 at width 4).
//! - 12 fewer `ed_mixed_add`s per scalar mult → ~700 ns saved on Apple
//!   M-series (each mixed-add is ≈ 58 ns / 7 field mults).
//! - The select loop scans 16 entries instead of 8 (~280 ns added),
//!   so net win is ~420 ns / call. Trade-off: table size grows from
//!   60 KiB to ~100 KiB `.rodata`.
//!
//! Storage: 52 × 16 = 832 `CachedPoint`s; each cached point is three
//! 5-limb `Fe`s = 120 bytes. Total `.rodata` ≈ 97 KiB.

use super::edwards::{
    BASEPOINT, CachedPoint, IDENTITY_CACHED, ed_add, ed_double, normalize, to_cached_affine,
};

/// Number of 5-bit windows. `52 * 5 = 260`, covers all 256 scalar bits
/// plus a 4-bit margin for carry propagation through the signed-digit
/// recoding (see [`super::base::recode_signed_5bit`]).
pub(super) const WINDOWS: usize = 52;

/// Entries per window: the `j`-th entry holds `(j + 1) · 32^i · B`,
/// `j ∈ {0, …, 15}`. The recoded digit `0` corresponds to the cached
/// identity element and is handled outside the table.
pub(super) const ENTRIES: usize = 16;

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
        // Advance the window base: window_base ← 32 · window_base (5 doubles).
        if i + 1 < WINDOWS {
            let d1 = ed_double(&window_base);
            let d2 = ed_double(&d1);
            let d3 = ed_double(&d2);
            let d4 = ed_double(&d3);
            window_base = ed_double(&d4);
        }
        i += 1;
    }
    table
}

pub(super) static TABLE: [[CachedPoint; ENTRIES]; WINDOWS] = build_table();

#[cfg(test)]
mod tests {
    use super::super::edwards::{IDENTITY, ct_select_cached, ed_mixed_add, ed_to_mont_u};
    use super::*;

    #[test]
    fn table_window_0_first_entry_is_basepoint_cached() {
        // TABLE[0][0] = 1 · 32^0 · B = BASEPOINT (cached).
        let expected = to_cached_affine(&BASEPOINT);
        assert_eq!(TABLE[0][0].y_minus_x, expected.y_minus_x);
        assert_eq!(TABLE[0][0].y_plus_x, expected.y_plus_x);
        assert_eq!(TABLE[0][0].t2d, expected.t2d);
    }

    #[test]
    fn table_window_0_second_entry_is_double_basepoint() {
        // TABLE[0][1] = 2 · 32^0 · B = 2·B (cached).
        let two_b = normalize(&ed_double(&BASEPOINT));
        let expected = to_cached_affine(&two_b);
        assert_eq!(TABLE[0][1].y_minus_x, expected.y_minus_x);
        assert_eq!(TABLE[0][1].y_plus_x, expected.y_plus_x);
        assert_eq!(TABLE[0][1].t2d, expected.t2d);
    }

    #[test]
    fn table_window_advances_by_32x() {
        // TABLE[1][0] = 1 · 32^1 · B = 32·B. Compute reference via five
        // doublings of the basepoint.
        let thirty_two_b = normalize(&ed_double(&ed_double(&ed_double(&ed_double(
            &ed_double(&BASEPOINT),
        )))));
        let expected = to_cached_affine(&thirty_two_b);
        assert_eq!(TABLE[1][0].y_minus_x, expected.y_minus_x);
        assert_eq!(TABLE[1][0].y_plus_x, expected.y_plus_x);
        assert_eq!(TABLE[1][0].t2d, expected.t2d);
    }

    #[test]
    fn signed_recoding_combs_to_basepoint_for_small_scalar() {
        // Build scalar = 33 = 1 · 32^0 + 1 · 32^1, i.e. window digits
        // [1, 1, 0, ..., 0] under the 5-bit decomposition.
        // Expected: result = (1·B) + (1·32·B) = 33·B.
        let mut acc = IDENTITY;
        let p0 = ct_select_cached(&TABLE[0], 1);
        acc = ed_mixed_add(&acc, &p0);
        let p1 = ct_select_cached(&TABLE[1], 1);
        acc = ed_mixed_add(&acc, &p1);
        let u = ed_to_mont_u(&acc);

        // Reference: compute 33·B via repeated addition.
        let mut ref_acc = BASEPOINT;
        let mut k = 0;
        while k < 32 {
            ref_acc = ed_add(&ref_acc, &BASEPOINT);
            k += 1;
        }
        let ref_u = ed_to_mont_u(&ref_acc);
        assert_eq!(u, ref_u);
    }
}
