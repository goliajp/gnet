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

/// Lane-wise quarter-round over four state vectors (each lane is its own
/// block, so no cross-lane movement is needed).
#[inline]
fn quarter_round(v: &mut [uint32x4_t; 16], a: usize, b: usize, c: usize, d: usize) {
    // SAFETY: NEON is baseline on aarch64; pure lane-wise arithmetic.
    unsafe {
        v[a] = vaddq_u32(v[a], v[b]);
        v[d] = rotl16(veorq_u32(v[d], v[a]));
        v[c] = vaddq_u32(v[c], v[d]);
        v[b] = rotl12(veorq_u32(v[b], v[c]));
        v[a] = vaddq_u32(v[a], v[b]);
        v[d] = rotl8(veorq_u32(v[d], v[a]));
        v[c] = vaddq_u32(v[c], v[d]);
        v[b] = rotl7(veorq_u32(v[b], v[c]));
    }
}

/// Generate four consecutive 64-byte keystream blocks (256 bytes) for block
/// counters `counter`, `counter+1`, `counter+2`, `counter+3`.
pub fn keystream4(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
    let st = init_state(key, counter, nonce);

    // Broadcast each state word across the four lanes; the counter word gets
    // a per-lane +0/+1/+2/+3 (wrapping, matching the scalar block counter).
    // SAFETY: NEON is baseline on aarch64; vdupq/vld1q are pure and the
    // `[0,1,2,3]` literal is a valid 4-u32 source.
    let mut v: [uint32x4_t; 16] = core::array::from_fn(|i| unsafe { vdupq_n_u32(st[i]) });
    v[12] = unsafe { vaddq_u32(v[12], vld1q_u32([0u32, 1, 2, 3].as_ptr())) };
    let init = v;

    for _ in 0..10 {
        quarter_round(&mut v, 0, 4, 8, 12);
        quarter_round(&mut v, 1, 5, 9, 13);
        quarter_round(&mut v, 2, 6, 10, 14);
        quarter_round(&mut v, 3, 7, 11, 15);
        quarter_round(&mut v, 0, 5, 10, 15);
        quarter_round(&mut v, 1, 6, 11, 12);
        quarter_round(&mut v, 2, 7, 8, 13);
        quarter_round(&mut v, 3, 4, 9, 14);
    }

    // SAFETY: pure lane-wise add of the original state.
    let added: [uint32x4_t; 16] = core::array::from_fn(|i| unsafe { vaddq_u32(v[i], init[i]) });

    // cols[w] = [block0.word_w, block1.word_w, block2.word_w, block3.word_w]
    let mut cols = [[0u32; 4]; 16];
    for (w, col) in cols.iter_mut().enumerate() {
        // SAFETY: `col` is a valid 4-u32 store target.
        unsafe { vst1q_u32(col.as_mut_ptr(), added[w]) };
    }

    let mut out = [0u8; 256];
    for (b, chunk) in out.chunks_exact_mut(64).enumerate() {
        for (w, word) in chunk.chunks_exact_mut(4).enumerate() {
            word.copy_from_slice(&cols[w][b].to_le_bytes());
        }
    }
    out
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
