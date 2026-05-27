//! NEON 4-way Keccak-f[1600] for aarch64. Runs four independent Keccak
//! sponges in lockstep by packing four 25-lane states across two `uint64x2_t`
//! registers per lane — `lo` holds streams 0 and 1, `hi` holds streams 2 and
//! 3. Each round of θ/ρ/π/χ/ι executes against four state interpretations at
//! once.
//!
//! Motivation: ML-KEM-768 matrix sampling needs 9 independent SHAKE128
//! streams (3×3 matrix of polynomials, each with its own (i,j) seed). Done
//! 4-at-a-time, that costs 2 × 4-way permutation + 1 × scalar instead of
//! 9 × scalar per absorbed block. Each 4-way permutation is ~1.7× the cost
//! of a scalar permutation (LLVM schedules NEON instructions tightly; the
//! 50-register working set spills modestly on Apple Silicon and lx64 NEON
//! cores alike), so the ratio drops from 9 → 2 × 1.7 + 1 ≈ 4.4 for matrix
//! generation. ML-KEM keygen and encrypt both benefit.
//!
//! Correctness invariant: 4-way output is bit-identical to four independent
//! scalar [`super::scalar::sponge`] calls. Verified by
//! `shake128_x4_matches_serial` and `keccak_f_x4_matches_scalar` in [`super`].

use core::arch::aarch64::*;

use super::scalar;

/// SHAKE128 rate in bytes (1600 − 2·128 = 1344 bits = 168 B).
const RATE: usize = 168;
/// Number of u64 lanes per rate-block (`RATE / 8`).
const RATE_LANES: usize = RATE / 8;

/// Four Keccak-f[1600] states packed lane-by-lane.
///
/// Each lane is held in two NEON registers:
/// - `lo: uint64x2_t = [state0_lane, state1_lane]`
/// - `hi: uint64x2_t = [state2_lane, state3_lane]`
///
/// 25 lanes × 2 vector registers = 50 logical registers. ARM NEON has 32
/// physical vector registers, so LLVM allocates the working set across
/// registers + a modest stack spill (a couple of lanes per round). On
/// Apple M-series and lx64 NEON cores this lands within ~1.5–1.8× the cost
/// of a single scalar Keccak-f[1600] — i.e. ~2.5× speedup for 4 streams.
#[derive(Clone, Copy)]
pub(super) struct State4 {
    lo: [uint64x2_t; 25],
    hi: [uint64x2_t; 25],
}

impl State4 {
    /// All-zero state.
    #[inline]
    fn zero() -> Self {
        // SAFETY: vdupq_n_u64 is a pure NEON broadcast intrinsic; aarch64
        // always has NEON, so the intrinsic is available unconditionally
        // under `cfg(target_arch = "aarch64")`.
        unsafe {
            let z = vdupq_n_u64(0);
            State4 {
                lo: [z; 25],
                hi: [z; 25],
            }
        }
    }
}

/// XOR a rate-block (168 B per stream) into the lane lanes of all four states.
///
/// # Safety
/// `aarch64` always has NEON, so the intrinsics are available unconditionally
/// inside `#[cfg(target_arch = "aarch64")]`. Inputs are plain `[u8; 168]`
/// fixed-size arrays, no pointer arithmetic outside well-formed loads.
#[inline]
unsafe fn xor_block_x4(s: &mut State4, blocks: &[[u8; RATE]; 4]) {
    for i in 0..RATE_LANES {
        let b0 = u64::from_le_bytes(blocks[0][i * 8..i * 8 + 8].try_into().unwrap());
        let b1 = u64::from_le_bytes(blocks[1][i * 8..i * 8 + 8].try_into().unwrap());
        let b2 = u64::from_le_bytes(blocks[2][i * 8..i * 8 + 8].try_into().unwrap());
        let b3 = u64::from_le_bytes(blocks[3][i * 8..i * 8 + 8].try_into().unwrap());
        // SAFETY: pure NEON XOR/load intrinsics, see #[inline]/cfg above.
        unsafe {
            let lo = vld1q_u64([b0, b1].as_ptr());
            let hi = vld1q_u64([b2, b3].as_ptr());
            s.lo[i] = veorq_u64(s.lo[i], lo);
            s.hi[i] = veorq_u64(s.hi[i], hi);
        }
    }
}

/// Apply one ρ/π step pair: rotate `t` by `ROT` (literal compile-time
/// constant; ROTC values are all in 1..=62) and store into lane `IDX`, then
/// update `t` to the old `s[IDX]` value. Operates on both `lo` and `hi`
/// halves so all four streams advance in lockstep.
///
/// The rotate is synthesized in-place as `(v << ROT) | (v >> (64 - ROT))`.
/// We can't share a `rotl64<const N>` helper because stable Rust forbids
/// const-generic arithmetic like `vshrq_n_u64::<{ 64 - N }>`. With macro
/// expansion the `64 - $rot` is computed at parse time as a plain literal.
macro_rules! rho_pi {
    ($s:expr, $t_lo:ident, $t_hi:ident, $idx:expr, $rot:expr) => {{
        let tmp_lo = $s.lo[$idx];
        let tmp_hi = $s.hi[$idx];
        $s.lo[$idx] = vorrq_u64(
            vshlq_n_u64::<{ $rot }>($t_lo),
            vshrq_n_u64::<{ 64 - $rot }>($t_lo),
        );
        $s.hi[$idx] = vorrq_u64(
            vshlq_n_u64::<{ $rot }>($t_hi),
            vshrq_n_u64::<{ 64 - $rot }>($t_hi),
        );
        $t_lo = tmp_lo;
        $t_hi = tmp_hi;
    }};
}

/// The Keccak-f[1600] permutation, 4-way. Applies 24 rounds of θ/ρ/π/χ/ι in
/// lockstep across the four states packed in `s`.
///
/// Round constants and rotation/permutation tables come from
/// [`super::scalar`] — same wire-level FIPS 202 spec, no re-derivation.
///
/// # Safety
/// All operations are NEON intrinsics gated by `cfg(target_arch = "aarch64")`.
/// No raw pointer arithmetic and no secret-dependent control flow (round
/// counts and table indices are public constants).
#[inline]
// The final rho_pi! invocation writes `t_lo`/`t_hi` that no later step
// reads; that's correct (the walk schedule terminates), and harmless.
#[allow(unused_assignments)]
unsafe fn keccak_f_x4(s: &mut State4) {
    for &rc in &scalar::RC {
        // θ: bc[i] = XOR_{j=0..5} s[5j + i]; then s[5j + i] ^= bc[(i+4)%5] ^ rotl(bc[(i+1)%5], 1)
        let mut bc_lo = [s.lo[0]; 5];
        let mut bc_hi = [s.hi[0]; 5];
        // SAFETY: NEON XOR intrinsics; aarch64-only and pure register ops.
        unsafe {
            for i in 0..5 {
                bc_lo[i] = veorq_u64(
                    veorq_u64(s.lo[i], s.lo[i + 5]),
                    veorq_u64(veorq_u64(s.lo[i + 10], s.lo[i + 15]), s.lo[i + 20]),
                );
                bc_hi[i] = veorq_u64(
                    veorq_u64(s.hi[i], s.hi[i + 5]),
                    veorq_u64(veorq_u64(s.hi[i + 10], s.hi[i + 15]), s.hi[i + 20]),
                );
            }
            for i in 0..5 {
                let prev_lo = bc_lo[(i + 4) % 5];
                let prev_hi = bc_hi[(i + 4) % 5];
                let nxt_lo = bc_lo[(i + 1) % 5];
                let nxt_hi = bc_hi[(i + 1) % 5];
                // rotl(nxt, 1) inlined: (nxt << 1) | (nxt >> 63)
                let rot_lo = vorrq_u64(vshlq_n_u64::<1>(nxt_lo), vshrq_n_u64::<63>(nxt_lo));
                let rot_hi = vorrq_u64(vshlq_n_u64::<1>(nxt_hi), vshrq_n_u64::<63>(nxt_hi));
                let t_lo = veorq_u64(prev_lo, rot_lo);
                let t_hi = veorq_u64(prev_hi, rot_hi);
                let mut j = 0;
                while j < 25 {
                    s.lo[j + i] = veorq_u64(s.lo[j + i], t_lo);
                    s.hi[j + i] = veorq_u64(s.hi[j + i], t_hi);
                    j += 5;
                }
            }

            // ρ and π: walk the (PILN, ROTC) schedule from scalar.rs. Each
            // step replaces lane PILN[i] with rotl(t, ROTC[i]) and pulls the
            // old PILN[i] into t for the next iteration. The rotates and
            // indices are all compile-time constants, so the macro expansion
            // monomorphizes 24 distinct `rotl64::<N>` calls — no runtime
            // dispatch.
            let mut t_lo = s.lo[1];
            let mut t_hi = s.hi[1];
            rho_pi!(s, t_lo, t_hi, 10, 1);
            rho_pi!(s, t_lo, t_hi, 7, 3);
            rho_pi!(s, t_lo, t_hi, 11, 6);
            rho_pi!(s, t_lo, t_hi, 17, 10);
            rho_pi!(s, t_lo, t_hi, 18, 15);
            rho_pi!(s, t_lo, t_hi, 3, 21);
            rho_pi!(s, t_lo, t_hi, 5, 28);
            rho_pi!(s, t_lo, t_hi, 16, 36);
            rho_pi!(s, t_lo, t_hi, 8, 45);
            rho_pi!(s, t_lo, t_hi, 21, 55);
            rho_pi!(s, t_lo, t_hi, 24, 2);
            rho_pi!(s, t_lo, t_hi, 4, 14);
            rho_pi!(s, t_lo, t_hi, 15, 27);
            rho_pi!(s, t_lo, t_hi, 23, 41);
            rho_pi!(s, t_lo, t_hi, 19, 56);
            rho_pi!(s, t_lo, t_hi, 13, 8);
            rho_pi!(s, t_lo, t_hi, 12, 25);
            rho_pi!(s, t_lo, t_hi, 2, 43);
            rho_pi!(s, t_lo, t_hi, 20, 62);
            rho_pi!(s, t_lo, t_hi, 14, 18);
            rho_pi!(s, t_lo, t_hi, 22, 39);
            rho_pi!(s, t_lo, t_hi, 9, 61);
            rho_pi!(s, t_lo, t_hi, 6, 20);
            rho_pi!(s, t_lo, t_hi, 1, 44);

            // χ: per row j, s[j+i] ^= (~s[j+(i+1)%5]) & s[j+(i+2)%5].
            // NEON's `vbicq_u64(a, b) = a & ~b` matches the inner expression
            // (with operands swapped from the scalar form).
            let mut j = 0;
            while j < 25 {
                let r0_lo = s.lo[j];
                let r1_lo = s.lo[j + 1];
                let r2_lo = s.lo[j + 2];
                let r3_lo = s.lo[j + 3];
                let r4_lo = s.lo[j + 4];
                let r0_hi = s.hi[j];
                let r1_hi = s.hi[j + 1];
                let r2_hi = s.hi[j + 2];
                let r3_hi = s.hi[j + 3];
                let r4_hi = s.hi[j + 4];

                s.lo[j] = veorq_u64(r0_lo, vbicq_u64(r2_lo, r1_lo));
                s.lo[j + 1] = veorq_u64(r1_lo, vbicq_u64(r3_lo, r2_lo));
                s.lo[j + 2] = veorq_u64(r2_lo, vbicq_u64(r4_lo, r3_lo));
                s.lo[j + 3] = veorq_u64(r3_lo, vbicq_u64(r0_lo, r4_lo));
                s.lo[j + 4] = veorq_u64(r4_lo, vbicq_u64(r1_lo, r0_lo));
                s.hi[j] = veorq_u64(r0_hi, vbicq_u64(r2_hi, r1_hi));
                s.hi[j + 1] = veorq_u64(r1_hi, vbicq_u64(r3_hi, r2_hi));
                s.hi[j + 2] = veorq_u64(r2_hi, vbicq_u64(r4_hi, r3_hi));
                s.hi[j + 3] = veorq_u64(r3_hi, vbicq_u64(r0_hi, r4_hi));
                s.hi[j + 4] = veorq_u64(r4_hi, vbicq_u64(r1_hi, r0_hi));
                j += 5;
            }

            // ι: XOR the round constant into all four states' lane 0.
            let rc_vec = vdupq_n_u64(rc);
            s.lo[0] = veorq_u64(s.lo[0], rc_vec);
            s.hi[0] = veorq_u64(s.hi[0], rc_vec);
        }
    }
}

/// Extract the current state's first `RATE` bytes per stream into the four
/// output blocks. Does not advance the sponge — callers wrap this with
/// [`keccak_f_x4`] for subsequent squeezes.
///
/// # Safety
/// NEON store + lane-extract intrinsics; aarch64-only.
#[inline]
unsafe fn extract_block_x4(s: &State4, outs: &mut [[u8; RATE]; 4]) {
    for i in 0..RATE_LANES {
        // SAFETY: vst1q_u64 stores 16 bytes (2 × u64) at the given pointer.
        // We provide a 16-byte aligned `[u64; 2]` stack temporary.
        unsafe {
            let mut lo_buf = [0u64; 2];
            vst1q_u64(lo_buf.as_mut_ptr(), s.lo[i]);
            outs[0][i * 8..i * 8 + 8].copy_from_slice(&lo_buf[0].to_le_bytes());
            outs[1][i * 8..i * 8 + 8].copy_from_slice(&lo_buf[1].to_le_bytes());

            let mut hi_buf = [0u64; 2];
            vst1q_u64(hi_buf.as_mut_ptr(), s.hi[i]);
            outs[2][i * 8..i * 8 + 8].copy_from_slice(&hi_buf[0].to_le_bytes());
            outs[3][i * 8..i * 8 + 8].copy_from_slice(&hi_buf[1].to_le_bytes());
        }
    }
}

/// SHAKE128 rate in bytes — re-exported so `mlkem` callers writing
/// streaming rejection samplers can size their buffers without depending on
/// FIPS 202 magic numbers literally.
pub(crate) const SHAKE128_RATE: usize = RATE;

/// Streaming SHAKE128 4-way sponge: absorbs four short seeds (each ≤ RATE)
/// with pad10*1, then exposes lockstep block squeezes.
///
/// "Short" seeds means each seed fits in a single rate-block — true for every
/// ML-KEM use case (sample_ntt sees 34-byte seeds, PRF sees 33-byte seeds).
/// Callers needing longer seeds should fall back to four serial scalar
/// sponges (the speedup matters most when the per-stream cost is dominated
/// by squeezing, which is the matrix-sampling case).
pub(crate) struct ShakeState4 {
    state: State4,
    /// `false` until the first [`next_block`](Self::next_block) call, then
    /// `true` thereafter. Marks whether the next extraction must be preceded
    /// by a permutation (matches the FIPS 202 sponge: extract → permute →
    /// extract → permute → ...).
    pumped_once: bool,
}

impl ShakeState4 {
    /// Absorb four short seeds (each ≤ RATE) and apply pad10*1 with the
    /// SHAKE domain byte `0x1f`. Returns a sponge ready to squeeze.
    pub(crate) fn absorb_short(seeds: [&[u8]; 4]) -> Self {
        let mut padded = [[0u8; RATE]; 4];
        for (slot, seed) in padded.iter_mut().zip(seeds.iter()) {
            assert!(
                seed.len() < RATE,
                "ShakeState4::absorb_short requires seed < RATE (168 B)"
            );
            slot[..seed.len()].copy_from_slice(seed);
            slot[seed.len()] = 0x1f;
            slot[RATE - 1] |= 0x80;
        }
        let mut state = State4::zero();
        // SAFETY: aarch64-only module; xor_block_x4 / keccak_f_x4 are NEON
        // pure-register pipelines guarded by the module-level cfg.
        unsafe {
            xor_block_x4(&mut state, &padded);
            keccak_f_x4(&mut state);
        }
        ShakeState4 {
            state,
            pumped_once: false,
        }
    }

    /// Squeeze a full rate-block (168 B per stream) into `outs`. Costs one
    /// 4-way Keccak-f[1600] per call after the first.
    pub(crate) fn next_block(&mut self, outs: &mut [[u8; SHAKE128_RATE]; 4]) {
        // SAFETY: aarch64-only module.
        unsafe {
            if self.pumped_once {
                keccak_f_x4(&mut self.state);
            }
            extract_block_x4(&self.state, outs);
        }
        self.pumped_once = true;
    }
}

/// SHAKE128 of four independent seeds in parallel. Bit-identical to four
/// serial [`super::shake128`] calls; verified by `shake128_x4_matches_serial`.
///
/// Falls back to four scalar sponges when any seed exceeds the rate
/// (uncommon — ML-KEM seeds are always short).
pub(super) fn shake128_x4(seeds: [&[u8]; 4], outs: [&mut [u8]; 4]) {
    let all_short = seeds.iter().all(|s| s.len() < RATE);
    if !all_short {
        // Rare path; mirror the scalar absorb+squeeze pipeline serially.
        let [s0, s1, s2, s3] = seeds;
        let [o0, o1, o2, o3] = outs;
        scalar::sponge(RATE, 0x1f, s0, o0);
        scalar::sponge(RATE, 0x1f, s1, o1);
        scalar::sponge(RATE, 0x1f, s2, o2);
        scalar::sponge(RATE, 0x1f, s3, o3);
        return;
    }

    let mut sponge = ShakeState4::absorb_short(seeds);
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

    /// 4-way Keccak-f[1600] must match four independent scalar invocations,
    /// bit-for-bit, on randomly varied initial states.
    // Cross-indexing between `scalars` (flat array) and `neon.lo / neon.hi`
    // (per-half register arrays) is clearer with bare index loops than with
    // double-zipped iterator pairs.
    #[allow(clippy::needless_range_loop)]
    #[test]
    fn keccak_f_x4_matches_scalar() {
        // 16 random quad-state inputs derived deterministically.
        for trial in 0..16u64 {
            let mut scalars: [[u64; 25]; 4] = [[0u64; 25]; 4];
            let mut neon = State4::zero();
            for s in 0..4 {
                for lane in 0..25 {
                    // Mixed bits — covers RC, ROTC, PILN behavior on diverse
                    // initial lane patterns.
                    let v = (trial.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                        .wrapping_add((s as u64).wrapping_mul(0xBB67_AE85_84CA_A73B))
                        .wrapping_add((lane as u64).wrapping_mul(0x3C6E_F372_FE94_F82B));
                    scalars[s][lane] = v;
                }
                scalar::keccak_f(&mut scalars[s]);
            }
            // Build the parallel input matching the original (pre-keccak_f) state.
            for s in 0..4 {
                for lane in 0..25 {
                    let pre = (trial.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                        .wrapping_add((s as u64).wrapping_mul(0xBB67_AE85_84CA_A73B))
                        .wrapping_add((lane as u64).wrapping_mul(0x3C6E_F372_FE94_F82B));
                    // SAFETY: lane-insert intrinsics on aarch64.
                    unsafe {
                        if s == 0 {
                            neon.lo[lane] = vsetq_lane_u64::<0>(pre, neon.lo[lane]);
                        } else if s == 1 {
                            neon.lo[lane] = vsetq_lane_u64::<1>(pre, neon.lo[lane]);
                        } else if s == 2 {
                            neon.hi[lane] = vsetq_lane_u64::<0>(pre, neon.hi[lane]);
                        } else {
                            neon.hi[lane] = vsetq_lane_u64::<1>(pre, neon.hi[lane]);
                        }
                    }
                }
            }
            // SAFETY: aarch64-only module.
            unsafe { keccak_f_x4(&mut neon) };
            for lane in 0..25 {
                // SAFETY: lane-extract intrinsics on aarch64.
                unsafe {
                    let g0 = vgetq_lane_u64::<0>(neon.lo[lane]);
                    let g1 = vgetq_lane_u64::<1>(neon.lo[lane]);
                    let g2 = vgetq_lane_u64::<0>(neon.hi[lane]);
                    let g3 = vgetq_lane_u64::<1>(neon.hi[lane]);
                    assert_eq!(g0, scalars[0][lane], "trial {trial} stream 0 lane {lane}");
                    assert_eq!(g1, scalars[1][lane], "trial {trial} stream 1 lane {lane}");
                    assert_eq!(g2, scalars[2][lane], "trial {trial} stream 2 lane {lane}");
                    assert_eq!(g3, scalars[3][lane], "trial {trial} stream 3 lane {lane}");
                }
            }
        }
    }
}
