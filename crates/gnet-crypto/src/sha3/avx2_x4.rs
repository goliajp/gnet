//! AVX2 4-way Keccak-f\[1600\] for x86_64. Mirror of [`super::neon_x4`] with
//! one `__m256i` per Keccak lane (4 × u64 — one per parallel stream), so
//! the 25-lane state lives in 25 `__m256i` registers. Bit-identical to
//! four independent scalar [`super::scalar::keccak_f`] calls, verified by
//! `keccak_f_x4_matches_scalar` in [`super::tests`].
//!
//! Motivation matches NEON: ML-KEM-768 matrix sampling needs 9
//! independent SHAKE128 streams (3×3 matrix of polynomials, each with
//! its own (i, j) seed). Done 4-at-a-time costs 2 × 4-way + 1 × scalar
//! instead of 9 × scalar — ratio drops to roughly 4.5/9 if the 4-way
//! permutation costs ~2.3× a scalar permutation (AVX2 64-bit shift +
//! XOR throughput is good; the 25-register working set spills to L1
//! modestly under x86_64's 16 ymm registers, but the spills land
//! in cache and don't dominate).
//!
//! Lane layout for one `__m256i state_lane`:
//! - lane 0 (low 64-bit) = stream 0's value
//! - lane 1               = stream 1
//! - lane 2               = stream 2
//! - lane 3 (high 64-bit) = stream 3
//!
//! The `_mm256_set_epi64x(b3, b2, b1, b0)` constructor reverses arg order
//! (high-to-low) — the body XOR-block path passes lanes in `(b3, b2,
//! b1, b0)` to land at lanes `(b0, b1, b2, b3)` matching this layout.

#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::{
    __m256i, _mm256_andnot_si256, _mm256_or_si256, _mm256_set_epi64x, _mm256_set1_epi64x,
    _mm256_setzero_si256, _mm256_slli_epi64, _mm256_srli_epi64, _mm256_storeu_si256,
    _mm256_xor_si256,
};

use super::scalar;

/// SHAKE128 rate in bytes (1600 − 2·128 = 1344 bits = 168 B).
const RATE: usize = 168;
/// Number of u64 lanes per rate-block (`RATE / 8`).
const RATE_LANES: usize = RATE / 8;

/// Four Keccak-f\[1600\] states packed lane-by-lane. Each `__m256i` holds
/// the same lane index from all four streams (lane 0 = stream 0, ...).
#[derive(Clone, Copy)]
pub(super) struct State4 {
    lanes: [__m256i; 25],
}

impl State4 {
    #[inline]
    fn zero() -> Self {
        // SAFETY: setzero is a pure AVX2 register init; the caller path
        // is gated on `is_x86_feature_detected!("avx2")` upstream.
        unsafe {
            let z = _mm256_setzero_si256();
            State4 { lanes: [z; 25] }
        }
    }
}

/// XOR a rate-block (168 B per stream) into the lane lanes of all four
/// states.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
unsafe fn xor_block_x4(s: &mut State4, blocks: &[[u8; RATE]; 4]) {
    for i in 0..RATE_LANES {
        let b0 = u64::from_le_bytes(blocks[0][i * 8..i * 8 + 8].try_into().unwrap()) as i64;
        let b1 = u64::from_le_bytes(blocks[1][i * 8..i * 8 + 8].try_into().unwrap()) as i64;
        let b2 = u64::from_le_bytes(blocks[2][i * 8..i * 8 + 8].try_into().unwrap()) as i64;
        let b3 = u64::from_le_bytes(blocks[3][i * 8..i * 8 + 8].try_into().unwrap()) as i64;
        // _mm256_set_epi64x takes args high-to-low, so passing
        // (b3, b2, b1, b0) lands at lanes (b0, b1, b2, b3).
        let v = _mm256_set_epi64x(b3, b2, b1, b0);
        s.lanes[i] = _mm256_xor_si256(s.lanes[i], v);
    }
}

/// One ρ/π step pair: rotate `t` left by `ROT` (literal compile-time
/// constant in 1..=62) and store into lane `IDX`, then update `t` to the
/// old `s[IDX]` value. The rotate is synthesised as
/// `(v << ROT) | (v >> (64 - ROT))` — AVX2 has no native 64-bit rotate
/// before AVX-512's `_mm256_rol_epi64`, so we open-code it.
///
/// Macro form because stable Rust forbids const-generic arithmetic like
/// `_mm256_srli_epi64::<{ 64 - N }>` inside a generic function. With macro
/// expansion the `64 - $rot` is computed at parse time as a plain literal.
macro_rules! rho_pi {
    ($s:expr, $t:ident, $idx:expr, $rot:expr) => {{
        let tmp = $s.lanes[$idx];
        $s.lanes[$idx] = _mm256_or_si256(
            _mm256_slli_epi64::<{ $rot }>($t),
            _mm256_srli_epi64::<{ 64 - $rot }>($t),
        );
        $t = tmp;
    }};
}

/// The Keccak-f\[1600\] permutation, 4-way. Applies 24 rounds of
/// θ/ρ/π/χ/ι in lockstep across the four states packed in `s`.
///
/// Round constants and rotation/permutation tables come from
/// [`super::scalar`] — same wire-level FIPS 202 spec, no re-derivation.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
// The final rho_pi! invocation writes `t` that no later step reads;
// that's correct (the walk schedule terminates), and harmless.
#[allow(unused_assignments)]
// index-driven inner loops are intentional — `i` indexes into both the
// state lanes (with `+5`/`+10`/`+15`/`+20` offsets that have no iterator
// equivalent) and the modular-rotation table; iterator chains would
// obscure the round structure here.
#[allow(clippy::needless_range_loop)]
unsafe fn keccak_f_x4(s: &mut State4) {
    for &rc in &scalar::RC {
        // θ: bc[i] = XOR_{j=0..5} s[5j + i];
        //    then s[5j + i] ^= bc[(i+4)%5] ^ rotl(bc[(i+1)%5], 1).
        let mut bc = [s.lanes[0]; 5];
        for i in 0..5 {
            bc[i] = _mm256_xor_si256(
                _mm256_xor_si256(s.lanes[i], s.lanes[i + 5]),
                _mm256_xor_si256(
                    _mm256_xor_si256(s.lanes[i + 10], s.lanes[i + 15]),
                    s.lanes[i + 20],
                ),
            );
        }
        for i in 0..5 {
            let prev = bc[(i + 4) % 5];
            let nxt = bc[(i + 1) % 5];
            // rotl(nxt, 1) inlined: (nxt << 1) | (nxt >> 63)
            let rot = _mm256_or_si256(_mm256_slli_epi64::<1>(nxt), _mm256_srli_epi64::<63>(nxt));
            let t = _mm256_xor_si256(prev, rot);
            let mut j = 0;
            while j < 25 {
                s.lanes[j + i] = _mm256_xor_si256(s.lanes[j + i], t);
                j += 5;
            }
        }

        // ρ and π: same (PILN, ROTC) schedule as super::neon_x4 — every
        // step replaces lane PILN[i] with rotl(t, ROTC[i]) and pulls the
        // old PILN[i] into t for the next iteration.
        let mut t = s.lanes[1];
        rho_pi!(s, t, 10, 1);
        rho_pi!(s, t, 7, 3);
        rho_pi!(s, t, 11, 6);
        rho_pi!(s, t, 17, 10);
        rho_pi!(s, t, 18, 15);
        rho_pi!(s, t, 3, 21);
        rho_pi!(s, t, 5, 28);
        rho_pi!(s, t, 16, 36);
        rho_pi!(s, t, 8, 45);
        rho_pi!(s, t, 21, 55);
        rho_pi!(s, t, 24, 2);
        rho_pi!(s, t, 4, 14);
        rho_pi!(s, t, 15, 27);
        rho_pi!(s, t, 23, 41);
        rho_pi!(s, t, 19, 56);
        rho_pi!(s, t, 13, 8);
        rho_pi!(s, t, 12, 25);
        rho_pi!(s, t, 2, 43);
        rho_pi!(s, t, 20, 62);
        rho_pi!(s, t, 14, 18);
        rho_pi!(s, t, 22, 39);
        rho_pi!(s, t, 9, 61);
        rho_pi!(s, t, 6, 20);
        rho_pi!(s, t, 1, 44);

        // χ: per row j, s[j+i] ^= (~s[j+(i+1)%5]) & s[j+(i+2)%5].
        //
        // AVX2's `_mm256_andnot_si256(a, b) = ~a & b` — note arg order:
        // NEON's `vbicq_u64(a, b) = a & ~b` becomes
        // `_mm256_andnot_si256(b, a)` with operands swapped.
        let mut j = 0;
        while j < 25 {
            let r0 = s.lanes[j];
            let r1 = s.lanes[j + 1];
            let r2 = s.lanes[j + 2];
            let r3 = s.lanes[j + 3];
            let r4 = s.lanes[j + 4];

            s.lanes[j] = _mm256_xor_si256(r0, _mm256_andnot_si256(r1, r2));
            s.lanes[j + 1] = _mm256_xor_si256(r1, _mm256_andnot_si256(r2, r3));
            s.lanes[j + 2] = _mm256_xor_si256(r2, _mm256_andnot_si256(r3, r4));
            s.lanes[j + 3] = _mm256_xor_si256(r3, _mm256_andnot_si256(r4, r0));
            s.lanes[j + 4] = _mm256_xor_si256(r4, _mm256_andnot_si256(r0, r1));
            j += 5;
        }

        // ι: XOR the round constant into all four states' lane 0.
        let rc_vec = _mm256_set1_epi64x(rc as i64);
        s.lanes[0] = _mm256_xor_si256(s.lanes[0], rc_vec);
    }
}

/// Extract the current state's first `RATE` bytes per stream into the
/// four output blocks. Does not advance the sponge.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
unsafe fn extract_block_x4(s: &State4, outs: &mut [[u8; RATE]; 4]) {
    // Stack temp aligned by Rust's [u64; 4] alignment (8 B, sufficient
    // for `_mm256_storeu_si256` which doesn't require 32-byte alignment).
    let mut tmp = [0u64; 4];
    for i in 0..RATE_LANES {
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, s.lanes[i]);
        outs[0][i * 8..i * 8 + 8].copy_from_slice(&tmp[0].to_le_bytes());
        outs[1][i * 8..i * 8 + 8].copy_from_slice(&tmp[1].to_le_bytes());
        outs[2][i * 8..i * 8 + 8].copy_from_slice(&tmp[2].to_le_bytes());
        outs[3][i * 8..i * 8 + 8].copy_from_slice(&tmp[3].to_le_bytes());
    }
}

/// SHAKE128 rate in bytes — same as the NEON variant; redefined here so
/// the x86_64 callers don't need to depend on the aarch64-only re-export
/// of `super::SHAKE128_RATE`.
pub(crate) const SHAKE128_RATE: usize = RATE;

/// Streaming SHAKE128 4-way sponge for the AVX2 path. Mirrors
/// [`super::neon_x4::ShakeState4`] one-to-one — same absorb_short
/// pad10*1 / SHAKE 0x1f convention, same next_block contract.
pub(crate) struct ShakeState4Avx2 {
    state: State4,
    pumped_once: bool,
}

impl ShakeState4Avx2 {
    /// Absorb four short seeds (each ≤ RATE) with SHAKE pad10*1.
    ///
    /// # Safety
    /// Caller must ensure the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn absorb_short(seeds: [&[u8]; 4]) -> Self {
        let mut padded = [[0u8; RATE]; 4];
        for (slot, seed) in padded.iter_mut().zip(seeds.iter()) {
            assert!(
                seed.len() < RATE,
                "ShakeState4Avx2::absorb_short requires seed < RATE (168 B)"
            );
            slot[..seed.len()].copy_from_slice(seed);
            slot[seed.len()] = 0x1f;
            slot[RATE - 1] |= 0x80;
        }
        let mut state = State4::zero();
        xor_block_x4(&mut state, &padded);
        keccak_f_x4(&mut state);
        ShakeState4Avx2 {
            state,
            pumped_once: false,
        }
    }

    /// Squeeze a full rate-block (168 B per stream) into `outs`. Costs
    /// one 4-way Keccak-f\[1600\] per call after the first.
    ///
    /// # Safety
    /// Caller must ensure the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn next_block(&mut self, outs: &mut [[u8; SHAKE128_RATE]; 4]) {
        if self.pumped_once {
            keccak_f_x4(&mut self.state);
        }
        extract_block_x4(&self.state, outs);
        self.pumped_once = true;
    }
}

/// SHAKE128 of four independent seeds in parallel (AVX2 path). Falls
/// back to four scalar sponges when any seed exceeds the rate, matching
/// the NEON variant.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn shake128_x4(seeds: [&[u8]; 4], outs: [&mut [u8]; 4]) {
    let all_short = seeds.iter().all(|s| s.len() < RATE);
    if !all_short {
        let [s0, s1, s2, s3] = seeds;
        let [o0, o1, o2, o3] = outs;
        scalar::sponge(RATE, 0x1f, s0, o0);
        scalar::sponge(RATE, 0x1f, s1, o1);
        scalar::sponge(RATE, 0x1f, s2, o2);
        scalar::sponge(RATE, 0x1f, s3, o3);
        return;
    }

    let mut sponge = ShakeState4Avx2::absorb_short(seeds);
    let max_len = outs.iter().map(|o| o.len()).max().unwrap_or(0);
    let n_blocks = max_len.div_ceil(RATE);

    let mut buf = [[0u8; RATE]; 4];
    let [o0, o1, o2, o3] = outs;
    let outs_mut: [&mut [u8]; 4] = [o0, o1, o2, o3];
    for blk_idx in 0..n_blocks {
        sponge.next_block(&mut buf);
        let off = blk_idx * RATE;
        for s in 0..4 {
            if outs_mut[s].len() <= off {
                continue;
            }
            let want = (outs_mut[s].len() - off).min(RATE);
            outs_mut[s][off..off + want].copy_from_slice(&buf[s][..want]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::arch::x86_64::{_mm256_extract_epi64, _mm256_insert_epi64};

    /// 4-way AVX2 Keccak-f\[1600\] must match four independent scalar
    /// invocations bit-for-bit on randomly varied initial states. Same
    /// shape as `super::neon_x4::tests::keccak_f_x4_matches_scalar`.
    #[allow(clippy::needless_range_loop)]
    #[test]
    fn keccak_f_x4_matches_scalar() {
        if !std::is_x86_feature_detected!("avx2") {
            eprintln!("skipping: host has no AVX2");
            return;
        }
        for trial in 0..16u64 {
            let mut scalars: [[u64; 25]; 4] = [[0u64; 25]; 4];
            let mut avx = State4::zero();
            for s in 0..4 {
                for lane in 0..25 {
                    let v = (trial.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                        .wrapping_add((s as u64).wrapping_mul(0xBB67_AE85_84CA_A73B))
                        .wrapping_add((lane as u64).wrapping_mul(0x3C6E_F372_FE94_F82B));
                    scalars[s][lane] = v;
                }
                scalar::keccak_f(&mut scalars[s]);
            }
            for s in 0..4 {
                for lane in 0..25 {
                    let pre = (trial.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                        .wrapping_add((s as u64).wrapping_mul(0xBB67_AE85_84CA_A73B))
                        .wrapping_add((lane as u64).wrapping_mul(0x3C6E_F372_FE94_F82B));
                    // SAFETY: AVX2 just detected.
                    unsafe {
                        avx.lanes[lane] = match s {
                            0 => _mm256_insert_epi64::<0>(avx.lanes[lane], pre as i64),
                            1 => _mm256_insert_epi64::<1>(avx.lanes[lane], pre as i64),
                            2 => _mm256_insert_epi64::<2>(avx.lanes[lane], pre as i64),
                            _ => _mm256_insert_epi64::<3>(avx.lanes[lane], pre as i64),
                        };
                    }
                }
            }
            // SAFETY: AVX2 just detected.
            unsafe { keccak_f_x4(&mut avx) };
            for lane in 0..25 {
                // SAFETY: AVX2 just detected.
                unsafe {
                    let g0 = _mm256_extract_epi64::<0>(avx.lanes[lane]) as u64;
                    let g1 = _mm256_extract_epi64::<1>(avx.lanes[lane]) as u64;
                    let g2 = _mm256_extract_epi64::<2>(avx.lanes[lane]) as u64;
                    let g3 = _mm256_extract_epi64::<3>(avx.lanes[lane]) as u64;
                    assert_eq!(g0, scalars[0][lane], "trial {trial} stream 0 lane {lane}");
                    assert_eq!(g1, scalars[1][lane], "trial {trial} stream 1 lane {lane}");
                    assert_eq!(g2, scalars[2][lane], "trial {trial} stream 2 lane {lane}");
                    assert_eq!(g3, scalars[3][lane], "trial {trial} stream 3 lane {lane}");
                }
            }
        }
    }
}
