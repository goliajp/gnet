//! Curve25519 field GF(2^255 − 19) in **radix 2^25.5** — ten alternating
//! 25/26-bit `i32` limbs. Designed to enable ARM NEON 2-way SIMD field
//! multiplication via `vmull_s32` (signed 32×32 → 64-bit widen mul) in a
//! later stone; this module is the **scalar correctness reference**
//! (S1 of the field-2255 refactor — see `gnet-bench-compare/TASKS.md`).
//!
//! Layout
//! ------
//! `Fe2255 = [i32; 10]`, where limb `i` carries weight `2^WEIGHTS[i]`:
//!
//!   limb : 0   1   2   3   4    5    6    7    8    9
//!   bits : 26  25  26  25  26   25   26   25   26   25  (sum = 255)
//!   wt   : 0   26  51  77  102  128  153  179  204  230
//!
//! The alternating 26-25 widths is the donna_neon / fiat-crypto convention
//! that makes every cross-product `a[i] * b[j]` (i32 × i32 → i64) land on
//! a half-integer-aligned weight, which the schoolbook fmul re-aligns
//! either to the same limb (`i+j` even-parity) or with a factor of 2
//! (`i+j` odd-parity).
//!
//! Reduction (mod 2^255 − 19): cross-products at position `k ≥ 10` fold
//! back to position `k − 10` with an extra factor of 19 (or 38 if the
//! odd-parity ×2 also applies). The post-mul carry chain re-clamps each
//! limb to its target bit width.
//!
//! Validation
//! ----------
//! Every op below is differentially KAT-tested against the
//! [`super::field`] radix-2^51 reference on random inputs in
//! `tests::roundtrip_*` — the byte-level `pack` outputs must agree, which
//! pins both the field arithmetic and the carry chain together.
//!
//! 0-dependency, `const fn` throughout so the future `base_table2255`
//! stone can build its precomputed comb table at compile time.

#![allow(dead_code, unused_imports)] // S1 — consumers (edwards2255, base_table2255) arrive in S3/S4.

mod mul;
mod serde;

#[cfg(target_arch = "aarch64")]
mod mul_neon;

pub(super) use mul::{fmul, fsqr, fsqr_n};
pub(super) use serde::{pack, unpack};

#[cfg(target_arch = "aarch64")]
pub(super) use mul_neon::fmul_pair_neon;

/// Field element in radix 2^25.5 — ten 25/26-bit signed limbs.
pub(super) type Fe2255 = [i32; 10];

/// Bit width of each limb when in "reduced" form. Even indices: 26 bits,
/// odd indices: 25 bits.
pub(super) const LIMB_BITS: [u32; 10] = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25];

/// `2^26 − 1` and `2^25 − 1` masks for the carry chain.
pub(super) const MASK26: i32 = (1 << 26) - 1;
pub(super) const MASK25: i32 = (1 << 25) - 1;

/// Field zero / one.
pub(super) const FE2255_ZERO: Fe2255 = [0i32; 10];
pub(super) const FE2255_ONE: Fe2255 = {
    let mut x = [0i32; 10];
    x[0] = 1;
    x
};

// ───── fadd / fsub ─────────────────────────────────────────────────────
//
// fadd is element-wise; result may be "slightly loose" (each limb up to
// ~2× the reduced range). fsub adds a large positive multiple of p to
// `a` before subtracting to keep limbs non-negative. The next fmul / fsqr
// or an explicit `reduce` call brings limbs back to canonical form.

/// `a + b` (per-limb sum).
pub(super) const fn fadd(a: &Fe2255, b: &Fe2255) -> Fe2255 {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
        a[5] + b[5],
        a[6] + b[6],
        a[7] + b[7],
        a[8] + b[8],
        a[9] + b[9],
    ]
}

/// `a − b` with a fixed bias so each output limb stays non-negative.
///
/// Bias: `2 · p` in radix 2^25.5 is `[2·(2^26−38), 2·(2^25−1), 2·(2^26−1),
/// 2·(2^25−1), 2·(2^26−1), 2·(2^25−1), 2·(2^26−1), 2·(2^25−1),
/// 2·(2^26−1), 2·(2^25−1)]`. (`2 · p = 2·2^255 − 38`; the high `2·2^255`
/// wraps to `2 · 19 = 38` which lands in limb 0 with `-38`. So
/// `2p = sum(LIMB_i × 2^WEIGHTS[i])` where LIMB_0 = `2·(2^26−1) − 38 + 2`
/// after carries from the 9 maxed limbs. Easier to express directly via
/// the per-limb max: each limb of the canonical `2·p` is its max value
/// minus 38 only at position 0.)
///
/// For our purpose we use a slightly larger bias — `4·p` — which gives
/// generous headroom for the subtraction without affecting the result
/// mod `p`.
pub(super) const fn fsub(a: &Fe2255, b: &Fe2255) -> Fe2255 {
    // 4p ≡ 0 (mod p). Limb decomposition:
    //   high wraparound (4 · 2^255) ≡ 4 · 19 = 76 → adds −76 to limb 0
    //   plus per-limb max values × 4 from the carry chain.
    // Concretely the easiest representation is:
    //   limb 0 = 4 · (2^26 − 1) − 76 = (1 << 28) − 80
    //   limb i odd = 4 · (2^25 − 1)  = (1 << 27) − 4
    //   limb i even (i>0) = 4 · (2^26 − 1) = (1 << 28) − 4
    // 4p decomposed per limb: limb 0 = 4·(2^26 − 19) = 2^28 − 76;
    // limb i odd = 4·(2^25 − 1) = 2^27 − 4; limb i even (i>0) = 4·(2^26 − 1)
    // = 2^28 − 4. Each is ≥ max canonical b[i], so result limbs stay ≥ 0.
    let bias0 = (1 << 28) - 76;
    let bias_e = (1 << 28) - 4;
    let bias_o = (1 << 27) - 4;
    [
        bias0 + a[0] - b[0],
        bias_o + a[1] - b[1],
        bias_e + a[2] - b[2],
        bias_o + a[3] - b[3],
        bias_e + a[4] - b[4],
        bias_o + a[5] - b[5],
        bias_e + a[6] - b[6],
        bias_o + a[7] - b[7],
        bias_e + a[8] - b[8],
        bias_o + a[9] - b[9],
    ]
}

// ───── carry / reduce ──────────────────────────────────────────────────

/// Carry-propagate a 10-element `i64` accumulator (post-fmul/fsqr output)
/// back to a reduced `Fe2255`. Two full passes guarantee all limbs land
/// in `[0, 2^25] ∪ [0, 2^26]` per their target width, modulo a final
/// `19` wrap-around at the top.
pub(super) const fn reduce_i64(mut t: [i64; 10]) -> Fe2255 {
    // First carry pass.
    let mut c: i64;
    c = t[0] >> 26;
    t[0] -= c << 26;
    t[1] += c;
    c = t[1] >> 25;
    t[1] -= c << 25;
    t[2] += c;
    c = t[2] >> 26;
    t[2] -= c << 26;
    t[3] += c;
    c = t[3] >> 25;
    t[3] -= c << 25;
    t[4] += c;
    c = t[4] >> 26;
    t[4] -= c << 26;
    t[5] += c;
    c = t[5] >> 25;
    t[5] -= c << 25;
    t[6] += c;
    c = t[6] >> 26;
    t[6] -= c << 26;
    t[7] += c;
    c = t[7] >> 25;
    t[7] -= c << 25;
    t[8] += c;
    c = t[8] >> 26;
    t[8] -= c << 26;
    t[9] += c;
    c = t[9] >> 25;
    t[9] -= c << 25;
    t[0] += c * 19; // wrap top to bottom

    // Second carry pass — handles any cascaded carry from the top wrap.
    c = t[0] >> 26;
    t[0] -= c << 26;
    t[1] += c;
    c = t[1] >> 25;
    t[1] -= c << 25;
    t[2] += c;
    c = t[2] >> 26;
    t[2] -= c << 26;
    t[3] += c;
    c = t[3] >> 25;
    t[3] -= c << 25;
    t[4] += c;
    c = t[4] >> 26;
    t[4] -= c << 26;
    t[5] += c;
    c = t[5] >> 25;
    t[5] -= c << 25;
    t[6] += c;
    c = t[6] >> 26;
    t[6] -= c << 26;
    t[7] += c;
    c = t[7] >> 25;
    t[7] -= c << 25;
    t[8] += c;
    c = t[8] >> 26;
    t[8] -= c << 26;
    t[9] += c;

    [
        t[0] as i32,
        t[1] as i32,
        t[2] as i32,
        t[3] as i32,
        t[4] as i32,
        t[5] as i32,
        t[6] as i32,
        t[7] as i32,
        t[8] as i32,
        t[9] as i32,
    ]
}

/// Full carry reduction of a loose `Fe2255` (e.g., after a long fadd
/// chain). Idempotent on already-reduced input.
pub(super) const fn reduce(a: &Fe2255) -> Fe2255 {
    reduce_i64([
        a[0] as i64,
        a[1] as i64,
        a[2] as i64,
        a[3] as i64,
        a[4] as i64,
        a[5] as i64,
        a[6] as i64,
        a[7] as i64,
        a[8] as i64,
        a[9] as i64,
    ])
}


// ───── finvert ─────────────────────────────────────────────────────────
//
// Same curve25519-donna addition chain as the radix-2^51 reference (254
// squarings + 11 multiplications). The chain is independent of limb
// representation, so we re-use the structure verbatim.

/// Field inverse `z^(p−2)` via Fermat's little theorem.
pub(super) const fn finvert(z: &Fe2255) -> Fe2255 {
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


// ───── tests — differential KAT vs radix-2^51 reference ─────────────

#[cfg(test)]
mod tests {
    use super::super::field::{pack as pack5, unpack as unpack5};
    use super::*;

    /// Deterministic xorshift64 byte stream for reproducible tests.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                for b in self.0.to_le_bytes() {
                    if out.len() < n {
                        out.push(b);
                    }
                }
            }
            out
        }
        fn arr32(&mut self) -> [u8; 32] {
            let v = self.bytes(32);
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            // Mask the high bit (canonical X25519 input format).
            a[31] &= 0x7f;
            a
        }
    }

    /// pack ∘ unpack must be the identity on canonical inputs (high bit
    /// of byte 31 already masked).
    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = Rng::new(0xdead_beef_cafe_babe);
        for _ in 0..32 {
            let bytes = rng.arr32();
            let fe = unpack(&bytes);
            let back = pack(&fe);
            assert_eq!(bytes, back, "pack∘unpack mismatch");
        }
    }

    /// Convert bytes through Fe5 and through Fe2255 — they must agree
    /// at the byte level (both implement GF(2^255 − 19), so canonical
    /// pack outputs are equal).
    #[test]
    fn fe2255_bytes_match_fe5_bytes() {
        let mut rng = Rng::new(0x1234_5678_9abc_def0);
        for _ in 0..32 {
            let bytes = rng.arr32();
            let fe5 = unpack5(&bytes);
            let fe2255 = unpack(&bytes);
            assert_eq!(pack5(&fe5), pack(&fe2255), "byte representations diverge");
        }
    }

    /// `fmul` differential KAT: Fe2255 fmul must agree with Fe5 fmul on
    /// random pairs, compared via canonical pack.
    #[test]
    fn fmul_matches_fe5() {
        let mut rng = Rng::new(0xa5a5_5a5a_a5a5_5a5a);
        for trial in 0..32 {
            let a_bytes = rng.arr32();
            let b_bytes = rng.arr32();
            let a5 = unpack5(&a_bytes);
            let b5 = unpack5(&b_bytes);
            let a2255 = unpack(&a_bytes);
            let b2255 = unpack(&b_bytes);
            let prod5 = super::super::field::fmul(&a5, &b5);
            let prod2255 = fmul(&a2255, &b2255);
            assert_eq!(pack5(&prod5), pack(&prod2255), "fmul mismatch trial {trial}");
        }
    }

    /// `fsqr` differential KAT.
    #[test]
    fn fsqr_matches_fe5() {
        let mut rng = Rng::new(0xf00d_face_b00b_dead);
        for trial in 0..32 {
            let a_bytes = rng.arr32();
            let a5 = unpack5(&a_bytes);
            let a2255 = unpack(&a_bytes);
            let sq5 = super::super::field::fsqr(&a5);
            let sq2255 = fsqr(&a2255);
            assert_eq!(pack5(&sq5), pack(&sq2255), "fsqr mismatch trial {trial}");
        }
    }

    /// `fadd` differential KAT.
    #[test]
    fn fadd_matches_fe5() {
        let mut rng = Rng::new(0x7e57_a661_1234_5678);
        for trial in 0..32 {
            let a_bytes = rng.arr32();
            let b_bytes = rng.arr32();
            let a5 = unpack5(&a_bytes);
            let b5 = unpack5(&b_bytes);
            let a2255 = unpack(&a_bytes);
            let b2255 = unpack(&b_bytes);
            let s5 = super::super::field::fadd(&a5, &b5);
            let s2255 = fadd(&a2255, &b2255);
            assert_eq!(pack5(&s5), pack(&s2255), "fadd mismatch trial {trial}");
        }
    }

    /// `fsub` differential KAT.
    #[test]
    fn fsub_matches_fe5() {
        let mut rng = Rng::new(0x600d_b00b_c0de_face);
        for trial in 0..32 {
            let a_bytes = rng.arr32();
            let b_bytes = rng.arr32();
            let a5 = unpack5(&a_bytes);
            let b5 = unpack5(&b_bytes);
            let a2255 = unpack(&a_bytes);
            let b2255 = unpack(&b_bytes);
            let d5 = super::super::field::fsub(&a5, &b5);
            let d2255 = fsub(&a2255, &b2255);
            assert_eq!(pack5(&d5), pack(&d2255), "fsub mismatch trial {trial}");
        }
    }

    /// `finvert` differential KAT — also exercises the full fmul/fsqr
    /// addition chain end-to-end.
    #[test]
    fn finvert_matches_fe5() {
        let mut rng = Rng::new(0x1111_2222_3333_4444);
        for trial in 0..16 {
            let a_bytes = rng.arr32();
            let a5 = unpack5(&a_bytes);
            let a2255 = unpack(&a_bytes);
            let inv5 = super::super::field::finvert(&a5);
            let inv2255 = finvert(&a2255);
            assert_eq!(pack5(&inv5), pack(&inv2255), "finvert mismatch trial {trial}");
        }
    }

    /// Informational microbench — Fe2255 scalar fmul vs Fe5 scalar fmul.
    /// Captures the radix-change overhead before any NEON work in S2.
    #[test]
    #[ignore = "informational microbench"]
    fn fmul_scalar_speed_vs_fe5() {
        use std::time::Instant;
        let mut rng = Rng::new(0x5eed_b00b_face_5a5a);
        let a_bytes = rng.arr32();
        let b_bytes = rng.arr32();
        let a5 = unpack5(&a_bytes);
        let b5 = unpack5(&b_bytes);
        let a2255 = unpack(&a_bytes);
        let b2255 = unpack(&b_bytes);

        for _ in 0..2_000 {
            let _ = std::hint::black_box(fmul(&a2255, &b2255));
            let _ = std::hint::black_box(super::super::field::fmul(&a5, &b5));
        }
        let iters = 200_000u32;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(fmul(
                std::hint::black_box(&a2255),
                std::hint::black_box(&b2255),
            ));
        }
        let ns_2255 = start.elapsed().as_nanos() as u64 / iters as u64;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(super::super::field::fmul(
                std::hint::black_box(&a5),
                std::hint::black_box(&b5),
            ));
        }
        let ns_5 = start.elapsed().as_nanos() as u64 / iters as u64;

        eprintln!("Fe2255 scalar fmul: {ns_2255} ns");
        eprintln!("Fe5    scalar fmul: {ns_5} ns");
        eprintln!("Fe2255 / Fe5 ratio: {:.2}×", ns_2255 as f64 / ns_5 as f64);
    }

    /// NEON 2-way pair fmul must be bit-identical to two serial scalar
    /// `fmul` invocations on the same inputs — the load-bearing KAT for
    /// `mul_neon.rs` and its `int32x2_t` packing.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn fmul_pair_neon_matches_two_scalars() {
        let mut rng = Rng::new(0xacac_5e5e_1010_2020);
        for trial in 0..32 {
            let a1_b = rng.arr32();
            let b1_b = rng.arr32();
            let a2_b = rng.arr32();
            let b2_b = rng.arr32();
            let a1 = unpack(&a1_b);
            let b1 = unpack(&b1_b);
            let a2 = unpack(&a2_b);
            let b2 = unpack(&b2_b);

            let (c1_neon, c2_neon) = fmul_pair_neon(&a1, &b1, &a2, &b2);
            let c1_scalar = fmul(&a1, &b1);
            let c2_scalar = fmul(&a2, &b2);

            assert_eq!(
                pack(&c1_neon),
                pack(&c1_scalar),
                "stream 1 mismatch trial {trial}"
            );
            assert_eq!(
                pack(&c2_neon),
                pack(&c2_scalar),
                "stream 2 mismatch trial {trial}"
            );
        }
    }

    /// Informational microbench — the **decision-maker** for B2.
    /// Compares NEON pair fmul vs **two serial Fe5 scalar fmul** (the
    /// real baseline an x25519_base_pair caller pays today). If NEON
    /// pair < 2× Fe5 scalar wall time, S3-S5 are worth landing.
    #[cfg(target_arch = "aarch64")]
    #[test]
    #[ignore = "informational microbench"]
    fn fmul_pair_neon_vs_2x_fe5_scalar() {
        use std::time::Instant;
        let mut rng = Rng::new(0xfeed_face_deca_beef);
        let a1_b = rng.arr32();
        let b1_b = rng.arr32();
        let a2_b = rng.arr32();
        let b2_b = rng.arr32();
        let a1_2255 = unpack(&a1_b);
        let b1_2255 = unpack(&b1_b);
        let a2_2255 = unpack(&a2_b);
        let b2_2255 = unpack(&b2_b);
        let a1_5 = unpack5(&a1_b);
        let b1_5 = unpack5(&b1_b);
        let a2_5 = unpack5(&a2_b);
        let b2_5 = unpack5(&b2_b);

        for _ in 0..2_000 {
            let _ = std::hint::black_box(fmul_pair_neon(
                &a1_2255, &b1_2255, &a2_2255, &b2_2255,
            ));
            let _ = std::hint::black_box(super::super::field::fmul(&a1_5, &b1_5));
            let _ = std::hint::black_box(super::super::field::fmul(&a2_5, &b2_5));
        }
        let iters = 200_000u32;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(fmul_pair_neon(
                std::hint::black_box(&a1_2255),
                std::hint::black_box(&b1_2255),
                std::hint::black_box(&a2_2255),
                std::hint::black_box(&b2_2255),
            ));
        }
        let neon_pair_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(super::super::field::fmul(
                std::hint::black_box(&a1_5),
                std::hint::black_box(&b1_5),
            ));
            let _ = std::hint::black_box(super::super::field::fmul(
                std::hint::black_box(&a2_5),
                std::hint::black_box(&b2_5),
            ));
        }
        let two_fe5_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        eprintln!("NEON pair fmul (Fe2255):  {neon_pair_ns} ns");
        eprintln!("2× scalar Fe5 fmul:        {two_fe5_ns} ns");
        eprintln!(
            "  speedup: {:.2}× (>1 means NEON wins)",
            two_fe5_ns as f64 / neon_pair_ns as f64
        );
    }

    /// Sanity: `a · a⁻¹ == 1` (mod p) for random non-zero `a`.
    #[test]
    fn finvert_inverse_property() {
        let one_bytes = pack(&FE2255_ONE);
        let mut rng = Rng::new(0x9999_8888_7777_6666);
        for trial in 0..16 {
            let a_bytes = rng.arr32();
            let a = unpack(&a_bytes);
            let a_inv = finvert(&a);
            let prod = fmul(&a, &a_inv);
            assert_eq!(pack(&prod), one_bytes, "a · a⁻¹ ≠ 1 trial {trial}");
        }
    }
}
