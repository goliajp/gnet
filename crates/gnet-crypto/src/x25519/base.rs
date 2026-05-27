//! Fixed-base X25519: `scalar · 9` (Montgomery basepoint) via an Edwards
//! comb table. ~3.5× faster than [`super::scalar::x25519`] for the
//! public-key-derivation case while preserving the same 32-byte LE
//! input / output API.
//!
//! Algorithm
//! 1. RFC 7748 §5 clamp.
//! 2. 5-bit signed-digit recoding of the 256-bit scalar into 52 digits
//!    in `[-15, 16]`. The recoding is branch-free over scalar bits; the
//!    carry chain is bounded by the clamp (bit 254 set, bit 255 clear).
//! 3. For each window `i`, constant-time select of the `|d_i|`-th cached
//!    Edwards multiple from [`super::base_table::TABLE`]`[i]`, conditional
//!    negate by `sign(d_i)`, and `ed_mixed_add` into the running
//!    extended-coords accumulator.
//! 4. Project the result back to the Curve25519 u-axis via the birational
//!    map `u = (Z + Y) / (Z - Y)` and serialize little-endian.

use super::base_table::{ENTRIES, TABLE, WINDOWS};
use super::edwards::{
    IDENTITY, Point, ct_negate_cached, ct_select_cached, ed_mixed_add, ed_to_mont_u,
    ed_to_mont_u_pair,
};
use super::scalar::clamp;

/// Bits per comb window (must match the radix of the table).
const WINDOW_BITS: usize = 5;

/// X25519 fixed-base: `scalar · 9` on the Curve25519 u-axis.
///
/// Equivalent to `x25519(scalar, &[9, 0, ..., 0])` but uses a
/// compile-time-precomputed Edwards basepoint comb (~97 KiB `.rodata`)
/// and runs ≈ 3.5× faster on the hot path. Use this for public-key
/// derivation; the general [`super::x25519`] handles the DH step.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let p = scalar_mult_basepoint(scalar);
    ed_to_mont_u(&p)
}

/// X25519 fixed-base for two scalars at once, sharing one [`finvert`]
/// (Curve25519's most expensive field op) across both via Montgomery's
/// batch-inversion trick.
///
/// Bit-identical to `(x25519_base(s1), x25519_base(s2))` — verified by
/// `x25519_base_pair_matches_two_singles` in the test module — but
/// roughly 2 µs faster per call on Apple M-series (one finvert is
/// ~2.1 µs; two independent calls would do two of them, batching does
/// one). Use it when a single function naturally derives two public
/// keys back-to-back, e.g. the Noise IK handshake's static + ephemeral
/// pair in `Initiator::new` / `Responder::new`.
pub fn x25519_base_pair(scalars: [&[u8; 32]; 2]) -> [[u8; 32]; 2] {
    let p1 = scalar_mult_basepoint(scalars[0]);
    let p2 = scalar_mult_basepoint(scalars[1]);
    let (u1, u2) = ed_to_mont_u_pair(&p1, &p2);
    [u1, u2]
}

/// Internal: comb-driven scalar multiplication of the Ed25519 basepoint,
/// returning the extended-coords result. Shared by [`x25519_base`] and
/// [`x25519_base_pair`] so both pay the same `clamp` + recode + 52 ×
/// (select, negate, mixed-add) cost; only the final affine-projection
/// step differs (single-inversion vs batched-inversion).
fn scalar_mult_basepoint(scalar: &[u8; 32]) -> Point {
    let mut s = *scalar;
    clamp(&mut s);
    let digits = recode_signed_5bit(&s);

    let mut acc = IDENTITY;
    for i in 0..WINDOWS {
        let d = digits[i];
        let abs_d = d.unsigned_abs();
        // neg_mask: 0 if d >= 0, u64::MAX if d < 0. Branch-free via the
        // sign extension of the i64 cast.
        let neg_mask = (i64::from(d) >> 63) as u64;
        let mut p = ct_select_cached::<ENTRIES>(&TABLE[i], abs_d);
        ct_negate_cached(&mut p, neg_mask);
        acc = ed_mixed_add(&acc, &p);
    }
    acc
}

/// 5-bit signed-digit recoding of the (clamped) scalar.
///
/// The recoding walks the 256-bit input in 5-bit windows low-to-high and
/// folds carries so each emitted digit lies in `[-15, 16]`. Each window
/// pulls 5 bits from the scalar byte stream (which doesn't align to byte
/// boundaries — handled by a sliding `u64` reservoir below).
///
/// The output `[i8; 52]` covers `52 * 5 = 260` bits, 4 bits more than the
/// 256-bit scalar — enough headroom for the carry to terminate cleanly
/// (a clamped scalar has bit 254 set + bit 255 clear, so the high windows
/// won't run away).
///
/// All operations are data-flow (no conditional branches on scalar
/// bits), so the recoding does not leak secret bits through timing.
fn recode_signed_5bit(s: &[u8; 32]) -> [i8; 52] {
    // Sliding 64-bit reservoir of unconsumed scalar bits. `bits_in_buf`
    // tracks how many bits are currently in `buf`. We refill from the
    // byte stream whenever the buffer would underflow a 5-bit pull.
    let mut buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    let mut byte_idx: usize = 0;

    let mut digits = [0i8; 52];
    let mut carry: i8 = 0;

    for digit in &mut digits {
        // Top up the reservoir so it holds at least 5 unread bits.
        while bits_in_buf < WINDOW_BITS as u32 && byte_idx < 32 {
            buf |= u64::from(s[byte_idx]) << bits_in_buf;
            bits_in_buf += 8;
            byte_idx += 1;
        }
        let raw_5bit = (buf & 0x1f) as i8;
        buf >>= WINDOW_BITS;
        bits_in_buf = bits_in_buf.saturating_sub(WINDOW_BITS as u32);

        let raw_with_carry = raw_5bit + carry;
        // If raw_with_carry > 16, emit (raw_with_carry − 32) and carry 1.
        // Branch-free: `(x + 15) >> 5` is 0 for x ≤ 16, 1 for x ≥ 17.
        let carry_next = (raw_with_carry + 15) >> 5;
        *digit = raw_with_carry - (carry_next << 5);
        carry = carry_next;
    }
    // Clamped X25519 scalars cannot leave a non-zero carry past the 52nd
    // window. 52 × 5 = 260 bits ≥ 255 + 5 headroom; the last few windows
    // see zero scalar bits and just absorb any residual carry.
    debug_assert_eq!(carry, 0);
    digits
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::scalar::x25519;

    fn base_point() -> [u8; 32] {
        let mut u = [0u8; 32];
        u[0] = 9;
        u
    }

    /// RFC 7748 §6.1 — Alice's public key from her secret via fixed-base.
    #[test]
    fn rfc7748_alice_public_key_via_basepoint_comb() {
        let priv_key = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(x25519_base(&priv_key), expected);
    }

    /// RFC 7748 §6.1 — Bob's public key from his secret via fixed-base.
    #[test]
    fn rfc7748_bob_public_key_via_basepoint_comb() {
        let priv_key = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        assert_eq!(x25519_base(&priv_key), expected);
    }

    /// Across 64 deterministic random scalars, `x25519_base(s)` must
    /// agree bit-for-bit with the Montgomery ladder `x25519(s, &[9, 0, …, 0])`.
    /// This is the load-bearing differential test.
    #[test]
    fn x25519_base_matches_montgomery_ladder_across_random_scalars() {
        let basepoint = base_point();
        // xorshift64 seeded with a fixed value for reproducibility.
        let mut state: u64 = 0xdead_beef_cafe_babe;
        for _ in 0..64 {
            let mut scalar = [0u8; 32];
            for chunk in scalar.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            let comb = x25519_base(&scalar);
            let ladder = x25519(&scalar, &basepoint);
            assert_eq!(comb, ladder, "comb vs ladder disagreement");
        }
    }

    /// Pair must be bit-identical to two independent x25519_base calls,
    /// across every scalar pair. This is the load-bearing test for the
    /// Montgomery batch-inversion shortcut in `ed_to_mont_u_pair`.
    #[test]
    fn x25519_base_pair_matches_two_singles() {
        let mut state: u64 = 0xc0de_cafe_1337_4242;
        let mut next_scalar = || {
            let mut scalar = [0u8; 32];
            for chunk in scalar.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            scalar
        };
        for _ in 0..32 {
            let s1 = next_scalar();
            let s2 = next_scalar();
            let pair = x25519_base_pair([&s1, &s2]);
            assert_eq!(pair[0], x25519_base(&s1));
            assert_eq!(pair[1], x25519_base(&s2));
        }
    }

    /// The pair entry-point must also match the Montgomery ladder
    /// reference (i.e., the whole pair path — comb + batched projection
    /// — is consistent with the canonical X25519 spec, not just
    /// internally consistent with the single-comb path).
    #[test]
    fn x25519_base_pair_matches_montgomery_ladder() {
        let basepoint = base_point();
        let s1 = [0x42u8; 32];
        let s2 = [0xa5u8; 32];
        let pair = x25519_base_pair([&s1, &s2]);
        assert_eq!(pair[0], x25519(&s1, &basepoint));
        assert_eq!(pair[1], x25519(&s2, &basepoint));
    }

    #[test]
    fn x25519_base_matches_ladder_for_all_zero_scalar() {
        let s = [0u8; 32];
        assert_eq!(x25519_base(&s), x25519(&s, &base_point()));
    }

    #[test]
    fn x25519_base_matches_ladder_for_all_ones_scalar() {
        let s = [0xffu8; 32];
        assert_eq!(x25519_base(&s), x25519(&s, &base_point()));
    }

    /// Microbench — x25519_base_pair vs two serial x25519_base calls.
    /// The expected speedup is Σ(2 × finvert) / Σ(1 × finvert + 5 × fmul)
    /// ≈ 2.1 µs saved out of ~10.7 µs serial = ~20 % per pair on Apple.
    #[test]
    #[ignore = "informational microbench"]
    fn x25519_base_pair_speedup_microbench() {
        use std::time::Instant;
        let s1 = [0x77u8; 32];
        let s2 = [0xa5u8; 32];

        for _ in 0..200 {
            let _ = x25519_base_pair([&s1, &s2]);
            let _ = x25519_base(&s1);
            let _ = x25519_base(&s2);
        }
        let iters = 5_000u32;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(x25519_base_pair([
                std::hint::black_box(&s1),
                std::hint::black_box(&s2),
            ]));
        }
        let pair_ns = start.elapsed().as_nanos() / u128::from(iters);

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(x25519_base(std::hint::black_box(&s1)));
            let _ = std::hint::black_box(x25519_base(std::hint::black_box(&s2)));
        }
        let serial_ns = start.elapsed().as_nanos() / u128::from(iters);

        eprintln!("x25519_base_pair: {pair_ns} ns");
        eprintln!("2× x25519_base:   {serial_ns} ns");
        eprintln!("  speedup: {:.2}×", serial_ns as f64 / pair_ns as f64);
    }

    /// Informational breakdown of x25519_base cost. Run with
    ///   `cargo test --release -p gnet-crypto --lib x25519::base::tests::x25519_base_breakdown_microbench -- --ignored --nocapture`.
    // Indexing both `digits` (by position) and `TABLE` (by window) inside
    // the same loop body is cleaner with explicit indices than nested
    // iterator pairs.
    #[allow(clippy::needless_range_loop)]
    #[test]
    #[ignore = "informational microbench"]
    fn x25519_base_breakdown_microbench() {
        use std::time::Instant;
        let s = [0x77u8; 32];

        // warm
        for _ in 0..200 {
            let _ = x25519_base(&s);
        }
        let iters = 5_000u32;

        // Whole-fn baseline
        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(x25519_base(std::hint::black_box(&s)));
        }
        let total = start.elapsed().as_nanos() / u128::from(iters);

        // Recoding-only
        let mut clamped = s;
        super::super::scalar::clamp(&mut clamped);
        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(recode_signed_5bit(std::hint::black_box(&clamped)));
        }
        let recode = start.elapsed().as_nanos() / u128::from(iters);

        // Select-loop only (no recode, no add, no project) — measures
        // ct_select_cached + ct_negate_cached cost across 64 windows.
        let digits = recode_signed_5bit(&clamped);
        let start = Instant::now();
        for _ in 0..iters {
            for i in 0..WINDOWS {
                let d = std::hint::black_box(digits[i]);
                let abs_d = d.unsigned_abs();
                let neg_mask = (i64::from(d) >> 63) as u64;
                let mut p = ct_select_cached(&TABLE[i], abs_d);
                ct_negate_cached(&mut p, neg_mask);
                std::hint::black_box(p);
            }
        }
        let select_only = start.elapsed().as_nanos() / u128::from(iters);

        // Add-loop only — reads from TABLE directly (digit 0 of each window),
        // measures 64 × ed_mixed_add cost.
        let start = Instant::now();
        for _ in 0..iters {
            let mut acc = IDENTITY;
            for i in 0..WINDOWS {
                let p = std::hint::black_box(TABLE[i][0]);
                acc = ed_mixed_add(&acc, &p);
            }
            std::hint::black_box(acc);
        }
        let add_only = start.elapsed().as_nanos() / u128::from(iters);

        // Final projection only.
        let mut acc = IDENTITY;
        for i in 0..WINDOWS {
            let p = TABLE[i][0];
            acc = ed_mixed_add(&acc, &p);
        }
        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(ed_to_mont_u(std::hint::black_box(&acc)));
        }
        let project_only = start.elapsed().as_nanos() / u128::from(iters);

        eprintln!("\nx25519_base breakdown ({iters} iters, ns/op):");
        eprintln!("  total x25519_base       : {total} ns");
        eprintln!("  recode_signed_5bit      : {recode} ns");
        eprintln!("  {WINDOWS} × (select + negate)  : {select_only} ns");
        eprintln!("  {WINDOWS} × ed_mixed_add       : {add_only} ns");
        eprintln!("  ed_to_mont_u            : {project_only} ns");
    }

    #[test]
    fn recoding_round_trip_arbitrary_scalar() {
        // recode_signed_5bit operates on the raw scalar. The signed-digit
        // sum Σ d_i · 32^i must equal the input scalar mod 2^256.
        //
        // Reconstruct in a 33-byte signed accumulator (one byte of
        // headroom). For each digit:
        //   - compute bit_idx = i · 5
        //   - shifted = digit << (bit_idx % 8)
        //   - add `shifted` straddling bytes [bit_idx / 8 ..] with proper
        //     sign-extension via i32 arithmetic.
        let s = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let digits = recode_signed_5bit(&s);
        let mut acc = [0i64; 33];
        for (i, &d) in digits.iter().enumerate() {
            let bit_idx = i * WINDOW_BITS;
            let byte_idx = bit_idx / 8;
            let shift = bit_idx % 8;
            // Digit ∈ [-15, 16], shifted by 0..=7 → value fits in i16.
            // Decompose into bytes: low = bits 0..8, mid = bits 8..16.
            let shifted = (i32::from(d)) << shift;
            acc[byte_idx] += i64::from(shifted) & 0xff;
            acc[byte_idx + 1] += i64::from(shifted >> 8);
        }
        // Signed carry-propagate byte by byte.
        for k in 0..32 {
            let v = acc[k];
            let low = v.rem_euclid(256);
            let high = (v - low) / 256;
            acc[k] = low;
            acc[k + 1] += high;
        }
        let mut got = [0u8; 32];
        for (k, byte) in got.iter_mut().enumerate() {
            assert!(
                (0..256).contains(&acc[k]),
                "carry leak at byte {k}: {:?}",
                acc[k]
            );
            *byte = acc[k] as u8;
        }
        assert_eq!(got, s);
    }
}
