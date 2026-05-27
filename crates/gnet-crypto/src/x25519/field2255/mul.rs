//! Fe2255 multiplication primitives: `fmul`, `fsqr`, `fsqr_n`.
//!
//! The schoolbook 10 × 10 = 100 cross-product layout is intentionally
//! flat (not a loop) so each i32 × i32 → i64 product is a simple
//! `imul` instruction and the inner accumulators stay in registers.
//! Two precomputation passes (× 19 wraparound and × 2 odd-parity
//! alignment) keep the hot inner sums to one `imul + iadd` per term.
//! See [`super::mod`] for the radix layout that drives the
//! cross-product factor table.

use super::{Fe2255, reduce_i64};

// ───── fmul ────────────────────────────────────────────────────────────
//
// Schoolbook 10 × 10 = 100 cross-products. For each output position
// `k ∈ 0..10`:
//
//   t[k] = Σ_{i+j=k}    factor(i,j) · a[i]·b[j]
//        + 19 · Σ_{i+j=k+10} factor(i,j) · a[i]·b[j]   (wraparound)
//
// where `factor(i,j) = 2 if (i odd AND j odd) else 1` (handles the
// half-integer weight 2^25.5 alignment of odd-index limbs).

/// Field multiply: `(a · b) mod (2^255 − 19)`.
pub(in super::super) const fn fmul(a: &Fe2255, b: &Fe2255) -> Fe2255 {
    // Promote operands to i64.
    let a0 = a[0] as i64;
    let a1 = a[1] as i64;
    let a2 = a[2] as i64;
    let a3 = a[3] as i64;
    let a4 = a[4] as i64;
    let a5 = a[5] as i64;
    let a6 = a[6] as i64;
    let a7 = a[7] as i64;
    let a8 = a[8] as i64;
    let a9 = a[9] as i64;
    let b0 = b[0] as i64;
    let b1 = b[1] as i64;
    let b2 = b[2] as i64;
    let b3 = b[3] as i64;
    let b4 = b[4] as i64;
    let b5 = b[5] as i64;
    let b6 = b[6] as i64;
    let b7 = b[7] as i64;
    let b8 = b[8] as i64;
    let b9 = b[9] as i64;

    // 19 · b[i] for the wraparound terms (b1 only needed via b1_38 below).
    let b2_19 = 19 * b2;
    let b3_19 = 19 * b3;
    let b4_19 = 19 * b4;
    let b5_19 = 19 * b5;
    let b6_19 = 19 * b6;
    let b7_19 = 19 * b7;
    let b8_19 = 19 * b8;
    let b9_19 = 19 * b9;

    // 2 · b[i] for the odd-parity alignment on no-wraparound positions.
    let b1_2 = 2 * b1;
    let b3_2 = 2 * b3;
    let b5_2 = 2 * b5;
    let b7_2 = 2 * b7;
    let b9_2 = 2 * b9;

    // 38 · b[i] = 19 × 2 × b[i] for wraparound + odd-parity together.
    let b1_38 = 19 * b1_2;
    let b3_38 = 19 * b3_2;
    let b5_38 = 19 * b5_2;
    let b7_38 = 19 * b7_2;
    let b9_38 = 19 * b9_2;

    // 2 · a[i] for odd-parity within in-range (no-wrap) cross-products.
    let a1_2 = 2 * a1;
    let a3_2 = 2 * a3;
    let a5_2 = 2 * a5;
    let a7_2 = 2 * a7;

    // Output cross-products. Each line is one (i, j) pair contributing
    // to t[k]. Group by k for clarity.

    // t[0] = a[i]·b[j] for i+j=0   (factor 1)
    //      + a[i]·b[j] for i+j=10  (factor 19 or 38)
    let t0 = a0 * b0
        + a1_2 * b9_19   // (1,9): odd-odd → 2, wrap → 19; combined via b9 alone? careful.
                          // a1_2 already has ×2, then ×19 from b9_19. Let me re-check.
                          // Actually: factor 2 (odd-odd) × factor 19 (wrap) = 38.
                          // Need both factors. b9_19 has 19 baked, a1_2 has 2 → product has 38. ✓
        + a2 * b8_19     // (2,8): even-even, wrap → 19
        + a3_2 * b7_19   // (3,7): odd-odd → 2, wrap → 19. 38 total. ✓
        + a4 * b6_19     // (4,6): even-even, 19
        + a5_2 * b5_19   // (5,5): odd-odd, 38
        + a6 * b4_19     // (6,4): even-even, 19
        + a7_2 * b3_19   // (7,3): odd-odd, 38
        + a8 * b2_19     // (8,2): even-even, 19
        + a9 * b1_38;    // (9,1): odd-odd, 38 — note this uses b1_38 (already has 38)

    // t[1] = i+j=1  (factor 1)
    //      + i+j=11 (factor 19, no odd-odd because 11 = odd, so one operand is even)
    let t1 = a0 * b1
        + a1 * b0
        + a2 * b9_19    // (2,9): even-odd, 19
        + a3 * b8_19    // (3,8): odd-even, 19
        + a4 * b7_19    // (4,7): even-odd, 19
        + a5 * b6_19    // (5,6): odd-even, 19
        + a6 * b5_19    // (6,5): even-odd, 19
        + a7 * b4_19    // (7,4): odd-even, 19
        + a8 * b3_19    // (8,3): even-odd, 19
        + a9 * b2_19;   // (9,2): odd-even, 19

    // t[2] = i+j=2  (factor 1 except (1,1) odd-odd → 2)
    //      + i+j=12 (factor 19 except (3,9), (5,7), (7,5), (9,3) odd-odd → 38)
    let t2 = a0 * b2
        + a1_2 * b1    // (1,1): odd-odd, 2
        + a2 * b0
        + a3_2 * b9_19 // (3,9): odd-odd, 38
        + a4 * b8_19   // (4,8): even-even, 19
        + a5_2 * b7_19 // (5,7): odd-odd, 38
        + a6 * b6_19   // (6,6): even-even, 19
        + a7_2 * b5_19 // (7,5): odd-odd, 38
        + a8 * b4_19   // (8,4): even-even, 19
        + a9 * b3_38;  // (9,3): odd-odd, 38

    // t[3] = i+j=3  (factor 1)
    //      + i+j=13 (factor 19, all mixed parity)
    let t3 = a0 * b3
        + a1 * b2
        + a2 * b1
        + a3 * b0
        + a4 * b9_19   // (4,9): even-odd, 19
        + a5 * b8_19   // (5,8): odd-even, 19
        + a6 * b7_19   // (6,7): even-odd, 19
        + a7 * b6_19   // (7,6): odd-even, 19
        + a8 * b5_19   // (8,5): even-odd, 19
        + a9 * b4_19;  // (9,4): odd-even, 19

    // t[4] = i+j=4  (factor 1 except (1,3), (3,1) odd-odd → 2)
    //      + i+j=14 (factor 19 except (5,9), (7,7), (9,5) odd-odd → 38)
    let t4 = a0 * b4
        + a1_2 * b3    // (1,3): odd-odd, 2
        + a2 * b2
        + a3_2 * b1    // (3,1): odd-odd, 2
        + a4 * b0
        + a5_2 * b9_19 // (5,9): odd-odd, 38
        + a6 * b8_19   // (6,8): even-even, 19
        + a7_2 * b7_19 // (7,7): odd-odd, 38
        + a8 * b6_19   // (8,6): even-even, 19
        + a9 * b5_38;  // (9,5): odd-odd, 38

    // t[5] = i+j=5  (factor 1)
    //      + i+j=15 (factor 19)
    let t5 = a0 * b5
        + a1 * b4
        + a2 * b3
        + a3 * b2
        + a4 * b1
        + a5 * b0
        + a6 * b9_19
        + a7 * b8_19
        + a8 * b7_19
        + a9 * b6_19;

    // t[6] = i+j=6 (factor 1 except (1,5), (3,3), (5,1) odd-odd → 2)
    //      + i+j=16 (factor 19 except (7,9), (9,7) odd-odd → 38)
    let t6 = a0 * b6
        + a1_2 * b5    // (1,5): odd-odd, 2
        + a2 * b4
        + a3_2 * b3    // (3,3): odd-odd, 2
        + a4 * b2
        + a5_2 * b1    // (5,1): odd-odd, 2
        + a6 * b0
        + a7_2 * b9_19 // (7,9): odd-odd, 38
        + a8 * b8_19   // (8,8): even-even, 19
        + a9 * b7_38;  // (9,7): odd-odd, 38

    // t[7] = i+j=7 (factor 1)
    //      + i+j=17 (factor 19)
    let t7 = a0 * b7
        + a1 * b6
        + a2 * b5
        + a3 * b4
        + a4 * b3
        + a5 * b2
        + a6 * b1
        + a7 * b0
        + a8 * b9_19
        + a9 * b8_19;

    // t[8] = i+j=8 (factor 1 except (1,7), (3,5), (5,3), (7,1) odd-odd → 2)
    //      + i+j=18 (only (9,9) — odd-odd → 38)
    let t8 = a0 * b8
        + a1_2 * b7    // (1,7): odd-odd, 2
        + a2 * b6
        + a3_2 * b5    // (3,5): odd-odd, 2
        + a4 * b4
        + a5_2 * b3    // (5,3): odd-odd, 2
        + a6 * b2
        + a7_2 * b1    // (7,1): odd-odd, 2
        + a8 * b0
        + a9 * b9_38;  // (9,9): odd-odd, 38

    // t[9] = i+j=9 (factor 1) — no wraparound here (no i+j=19).
    let t9 = a0 * b9
        + a1 * b8
        + a2 * b7
        + a3 * b6
        + a4 * b5
        + a5 * b4
        + a6 * b3
        + a7 * b2
        + a8 * b1
        + a9 * b0;

    reduce_i64([t0, t1, t2, t3, t4, t5, t6, t7, t8, t9])
}

/// Square: `(a²) mod (2^255 − 19)`. Could be optimized to ~½ the work
/// of `fmul(a, a)` (since `a[i]·a[j] == a[j]·a[i]`), but for S1 we just
/// delegate to fmul — correctness reference. S2 will introduce a
/// dedicated squaring path.
pub(in super::super) const fn fsqr(a: &Fe2255) -> Fe2255 {
    fmul(a, a)
}

/// Apply [`fsqr`] `n` times in a row. Used by [`finvert`].
pub(in super::super) const fn fsqr_n(mut a: Fe2255, n: usize) -> Fe2255 {
    let mut i = 0;
    while i < n {
        a = fsqr(&a);
        i += 1;
    }
    a
}
