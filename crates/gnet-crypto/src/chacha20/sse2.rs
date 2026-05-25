//! 4-way SSE2 ChaCha20 (x86_64): four consecutive blocks in parallel, one
//! per SIMD lane — the same shuffle-free approach as the NEON path. SSE2 is
//! baseline on x86_64, so no runtime feature detection is needed.
//!
//! Constant-time. Validated against the scalar reference by
//! `keystream4_matches_scalar` and the parent module's KATs.

use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_or_si128, _mm_set1_epi32, _mm_setr_epi32, _mm_slli_epi32,
    _mm_srli_epi32, _mm_storeu_si128, _mm_xor_si128,
};

use super::init_state;

#[inline]
fn rotl16(v: __m128i) -> __m128i {
    // SAFETY: SSE2 is baseline on x86_64; pure register shift/or.
    unsafe { _mm_or_si128(_mm_slli_epi32::<16>(v), _mm_srli_epi32::<16>(v)) }
}
#[inline]
fn rotl12(v: __m128i) -> __m128i {
    // SAFETY: see rotl16.
    unsafe { _mm_or_si128(_mm_slli_epi32::<12>(v), _mm_srli_epi32::<20>(v)) }
}
#[inline]
fn rotl8(v: __m128i) -> __m128i {
    // SAFETY: see rotl16.
    unsafe { _mm_or_si128(_mm_slli_epi32::<8>(v), _mm_srli_epi32::<24>(v)) }
}
#[inline]
fn rotl7(v: __m128i) -> __m128i {
    // SAFETY: see rotl16.
    unsafe { _mm_or_si128(_mm_slli_epi32::<7>(v), _mm_srli_epi32::<25>(v)) }
}

/// Lane-wise quarter-round over four state vectors.
#[inline]
fn quarter_round(v: &mut [__m128i; 16], a: usize, b: usize, c: usize, d: usize) {
    // SAFETY: SSE2 is baseline on x86_64; pure lane-wise arithmetic.
    unsafe {
        v[a] = _mm_add_epi32(v[a], v[b]);
        v[d] = rotl16(_mm_xor_si128(v[d], v[a]));
        v[c] = _mm_add_epi32(v[c], v[d]);
        v[b] = rotl12(_mm_xor_si128(v[b], v[c]));
        v[a] = _mm_add_epi32(v[a], v[b]);
        v[d] = rotl8(_mm_xor_si128(v[d], v[a]));
        v[c] = _mm_add_epi32(v[c], v[d]);
        v[b] = rotl7(_mm_xor_si128(v[b], v[c]));
    }
}

/// Generate four consecutive 64-byte keystream blocks (256 bytes) for block
/// counters `counter`, `counter+1`, `counter+2`, `counter+3`.
pub fn keystream4(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
    let st = init_state(key, counter, nonce);

    // SAFETY (each below): SSE2 is baseline on x86_64; set1/setr/add are pure
    // and the stores below are in-bounds with unaligned-permitting `storeu`.
    let mut v: [__m128i; 16] = core::array::from_fn(|i| unsafe { _mm_set1_epi32(st[i] as i32) });
    v[12] = unsafe { _mm_add_epi32(v[12], _mm_setr_epi32(0, 1, 2, 3)) };
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

    let added: [__m128i; 16] = core::array::from_fn(|i| unsafe { _mm_add_epi32(v[i], init[i]) });

    let mut cols = [[0u32; 4]; 16];
    for (w, col) in cols.iter_mut().enumerate() {
        // SAFETY: `col` is a valid 16-byte store target; storeu is unaligned.
        unsafe { _mm_storeu_si128(col.as_mut_ptr().cast::<__m128i>(), added[w]) };
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
