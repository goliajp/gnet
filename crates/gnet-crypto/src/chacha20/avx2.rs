//! 8-way AVX2 ChaCha20 (x86_64, runtime-detected): eight blocks per 256-bit
//! lane. Used when the CPU reports AVX2; callers fall back to the SSE2 path
//! otherwise. Same shuffle-free structure as the SSE2/NEON paths.

use core::arch::x86_64::{
    __m256i, _mm256_add_epi32, _mm256_or_si256, _mm256_set1_epi32, _mm256_setr_epi32,
    _mm256_slli_epi32, _mm256_srli_epi32, _mm256_storeu_si256, _mm256_xor_si256,
};

use super::init_state;

/// Rotate-left each 32-bit lane by `$l` bits (`$r = 32 - $l`).
macro_rules! rotl {
    ($x:expr, $l:literal, $r:literal) => {
        _mm256_or_si256(_mm256_slli_epi32::<$l>($x), _mm256_srli_epi32::<$r>($x))
    };
}

/// Lane-wise ChaCha quarter-round over four state vectors.
macro_rules! qr {
    ($v:expr, $a:literal, $b:literal, $c:literal, $d:literal) => {{
        $v[$a] = _mm256_add_epi32($v[$a], $v[$b]);
        $v[$d] = rotl!(_mm256_xor_si256($v[$d], $v[$a]), 16, 16);
        $v[$c] = _mm256_add_epi32($v[$c], $v[$d]);
        $v[$b] = rotl!(_mm256_xor_si256($v[$b], $v[$c]), 12, 20);
        $v[$a] = _mm256_add_epi32($v[$a], $v[$b]);
        $v[$d] = rotl!(_mm256_xor_si256($v[$d], $v[$a]), 8, 24);
        $v[$c] = _mm256_add_epi32($v[$c], $v[$d]);
        $v[$b] = rotl!(_mm256_xor_si256($v[$b], $v[$c]), 7, 25);
    }};
}

/// Generate eight consecutive 64-byte keystream blocks (512 bytes) for block
/// counters `counter` .. `counter + 7`.
///
/// # Safety
/// The CPU must support AVX2 (the caller checks `is_x86_feature_detected!`).
#[target_feature(enable = "avx2")]
pub unsafe fn keystream8(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 512] {
    let st = init_state(key, counter, nonce);
    // SAFETY: AVX2 is guaranteed by the `target_feature` attribute / caller;
    // all ops are pure lane-wise arithmetic and the stores are in-bounds with
    // unaligned-permitting `storeu`.
    unsafe {
        let mut v: [__m256i; 16] = [_mm256_set1_epi32(0); 16];
        for (vi, &si) in v.iter_mut().zip(st.iter()) {
            *vi = _mm256_set1_epi32(si as i32);
        }
        v[12] = _mm256_add_epi32(v[12], _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
        let init = v;

        for _ in 0..10 {
            qr!(v, 0, 4, 8, 12);
            qr!(v, 1, 5, 9, 13);
            qr!(v, 2, 6, 10, 14);
            qr!(v, 3, 7, 11, 15);
            qr!(v, 0, 5, 10, 15);
            qr!(v, 1, 6, 11, 12);
            qr!(v, 2, 7, 8, 13);
            qr!(v, 3, 4, 9, 14);
        }

        let mut added: [__m256i; 16] = [_mm256_set1_epi32(0); 16];
        for (a, (&vi, &ii)) in added.iter_mut().zip(v.iter().zip(init.iter())) {
            *a = _mm256_add_epi32(vi, ii);
        }

        // cols[w] = [block0.word_w, .., block7.word_w]
        let mut cols = [[0u32; 8]; 16];
        for (w, col) in cols.iter_mut().enumerate() {
            _mm256_storeu_si256(col.as_mut_ptr().cast::<__m256i>(), added[w]);
        }

        let mut out = [0u8; 512];
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

    /// The 8-way keystream must equal eight consecutive scalar `block()`
    /// outputs (skipped on CPUs without AVX2).
    #[test]
    fn keystream8_matches_scalar() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xa5);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        for &c in &[0u32, 1, 7, 1000, u32::MAX - 3, u32::MAX] {
            // SAFETY: guarded by the is_x86_feature_detected check above.
            let ks8 = unsafe { keystream8(&key, c, &nonce) };
            let mut expected = [0u8; 512];
            for (k, chunk) in expected.chunks_exact_mut(64).enumerate() {
                chunk.copy_from_slice(&block(&key, c.wrapping_add(k as u32), &nonce));
            }
            assert_eq!(ks8, expected);
        }
    }
}
