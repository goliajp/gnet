//! 4-way NEON ChaCha20 (aarch64): four consecutive blocks computed in
//! parallel, one block per SIMD lane. Because each lane is an independent
//! block, the diagonal rounds need no lane shuffles — they just address
//! different state vectors, which is what makes 4-way faster than a
//! single-block SIMD pass.
//!
//! Constant-time (no data-dependent branches). Validated against the scalar
//! reference by `keystream4_matches_scalar` and the parent module's KATs.

use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vld1q_u32, vorrq_u32, vshlq_n_u32, vshrq_n_u32,
    vst1q_u32,
};

use super::init_state;

#[inline]
fn rotl16(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: NEON is baseline on aarch64; pure register shift/or.
    unsafe { vorrq_u32(vshlq_n_u32::<16>(v), vshrq_n_u32::<16>(v)) }
}
#[inline]
fn rotl12(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: see rotl16.
    unsafe { vorrq_u32(vshlq_n_u32::<12>(v), vshrq_n_u32::<20>(v)) }
}
#[inline]
fn rotl8(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: see rotl16.
    unsafe { vorrq_u32(vshlq_n_u32::<8>(v), vshrq_n_u32::<24>(v)) }
}
#[inline]
fn rotl7(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: see rotl16.
    unsafe { vorrq_u32(vshlq_n_u32::<7>(v), vshrq_n_u32::<25>(v)) }
}

/// Generate four consecutive 64-byte keystream blocks (256 bytes) for block
/// counters `counter`, `counter+1`, `counter+2`, `counter+3`.
///
/// Each of the 16 state words lives in its own SSA local (`v0..v15` and
/// `init0..init15`) rather than inside an `[uint32x4_t; 16]` array — this is a
/// 2026-05-28 v0.9 intrinsic-schedule pre-flight: the array form pushed
/// LLVM's register allocator past the 32-NEON-register physical ceiling and
/// it spilled inside the inner round loop. Independent locals let the AArch64
/// backend see the data flow as 16 separate SSA chains and pick assignments
/// without the array-borrow indirection.
pub fn keystream4(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
    let st = init_state(key, counter, nonce);

    // SAFETY: NEON is baseline on aarch64; vdupq/vld1q/vaddq are pure and the
    // `[0,1,2,3]` literal is a valid 4-u32 source.
    unsafe {
        // Broadcast each state word across the four lanes; the counter word
        // gets a per-lane +0/+1/+2/+3 (wrapping, matching the scalar block
        // counter).
        let init0 = vdupq_n_u32(st[0]);
        let init1 = vdupq_n_u32(st[1]);
        let init2 = vdupq_n_u32(st[2]);
        let init3 = vdupq_n_u32(st[3]);
        let init4 = vdupq_n_u32(st[4]);
        let init5 = vdupq_n_u32(st[5]);
        let init6 = vdupq_n_u32(st[6]);
        let init7 = vdupq_n_u32(st[7]);
        let init8 = vdupq_n_u32(st[8]);
        let init9 = vdupq_n_u32(st[9]);
        let init10 = vdupq_n_u32(st[10]);
        let init11 = vdupq_n_u32(st[11]);
        let init12 = vaddq_u32(vdupq_n_u32(st[12]), vld1q_u32([0u32, 1, 2, 3].as_ptr()));
        let init13 = vdupq_n_u32(st[13]);
        let init14 = vdupq_n_u32(st[14]);
        let init15 = vdupq_n_u32(st[15]);

        let mut v0 = init0;
        let mut v1 = init1;
        let mut v2 = init2;
        let mut v3 = init3;
        let mut v4 = init4;
        let mut v5 = init5;
        let mut v6 = init6;
        let mut v7 = init7;
        let mut v8 = init8;
        let mut v9 = init9;
        let mut v10 = init10;
        let mut v11 = init11;
        let mut v12 = init12;
        let mut v13 = init13;
        let mut v14 = init14;
        let mut v15 = init15;

        // Lane-wise quarter-round: four independent ChaCha20 blocks, one per
        // lane. No cross-lane movement is needed since each lane is its own
        // block — the diagonal rounds just address different state vectors.
        macro_rules! qr {
            ($a:ident, $b:ident, $c:ident, $d:ident) => {
                $a = vaddq_u32($a, $b);
                $d = rotl16(veorq_u32($d, $a));
                $c = vaddq_u32($c, $d);
                $b = rotl12(veorq_u32($b, $c));
                $a = vaddq_u32($a, $b);
                $d = rotl8(veorq_u32($d, $a));
                $c = vaddq_u32($c, $d);
                $b = rotl7(veorq_u32($b, $c));
            };
        }

        for _ in 0..10 {
            // column round
            qr!(v0, v4, v8, v12);
            qr!(v1, v5, v9, v13);
            qr!(v2, v6, v10, v14);
            qr!(v3, v7, v11, v15);
            // diagonal round
            qr!(v0, v5, v10, v15);
            qr!(v1, v6, v11, v12);
            qr!(v2, v7, v8, v13);
            qr!(v3, v4, v9, v14);
        }

        let added: [uint32x4_t; 16] = [
            vaddq_u32(v0, init0),
            vaddq_u32(v1, init1),
            vaddq_u32(v2, init2),
            vaddq_u32(v3, init3),
            vaddq_u32(v4, init4),
            vaddq_u32(v5, init5),
            vaddq_u32(v6, init6),
            vaddq_u32(v7, init7),
            vaddq_u32(v8, init8),
            vaddq_u32(v9, init9),
            vaddq_u32(v10, init10),
            vaddq_u32(v11, init11),
            vaddq_u32(v12, init12),
            vaddq_u32(v13, init13),
            vaddq_u32(v14, init14),
            vaddq_u32(v15, init15),
        ];

        // cols[w] = [block0.word_w, block1.word_w, block2.word_w, block3.word_w]
        let mut cols = [[0u32; 4]; 16];
        for (w, col) in cols.iter_mut().enumerate() {
            vst1q_u32(col.as_mut_ptr(), added[w]);
        }

        let mut out = [0u8; 256];
        for (b, chunk) in out.chunks_exact_mut(64).enumerate() {
            for (w, word) in chunk.chunks_exact_mut(4).enumerate() {
                word.copy_from_slice(&cols[w][b].to_le_bytes());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chacha20::block;

    /// The 4-way keystream must equal four consecutive scalar `block()`
    /// outputs, including across the 32-bit counter wrap.
    #[test]
    fn keystream4_matches_scalar() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xa5);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        for &c in &[0u32, 1, 5, 1000, u32::MAX - 1, u32::MAX] {
            let ks4 = keystream4(&key, c, &nonce);
            let mut expected = [0u8; 256];
            for (k, chunk) in expected.chunks_exact_mut(64).enumerate() {
                chunk.copy_from_slice(&block(&key, c.wrapping_add(k as u32), &nonce));
            }
            assert_eq!(ks4, expected);
        }
    }
}
