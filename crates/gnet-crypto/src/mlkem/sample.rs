//! ML-KEM (FIPS 203) sampling: `SampleNTT` (Algorithm 7, rejection sampling of
//! a uniform NTT-domain polynomial from a SHAKE-128 stream) and `SamplePolyCBD`
//! (Algorithm 8, the centered binomial noise) with its SHAKE-256 PRF. ML-KEM-768
//! uses η = 2 throughout.

use super::ntt::Q;
use crate::sha3::{self, Xof};

/// `SampleNTT`: a uniform polynomial in the NTT domain from a 34-byte seed
/// (`ρ ‖ i ‖ j`), via rejection sampling of 12-bit values from SHAKE-128.
/// Reads SHAKE128 a full rate-block (168 bytes) at a time into a stack
/// buffer; consumes 12-bit candidates from that buffer until the polynomial
/// fills. This amortizes the per-call squeeze overhead across 56 candidates
/// per Keccak permutation.
pub fn sample_ntt(seed: &[u8]) -> [i16; 256] {
    const RATE: usize = 168;
    let mut xof = Xof::shake128(seed);
    let mut a = [0i16; 256];
    let mut j = 0usize;
    let mut buf = [0u8; RATE];
    while j < 256 {
        xof.squeeze(&mut buf);
        // A 168-byte block carries 56 groups of 3 bytes = 112 candidates.
        let mut off = 0;
        while off + 3 <= RATE && j < 256 {
            let b0 = buf[off] as u16;
            let b1 = buf[off + 1] as u16;
            let b2 = buf[off + 2] as u16;
            let d1 = b0 | ((b1 & 0x0f) << 8);
            let d2 = (b1 >> 4) | (b2 << 4);
            if d1 < Q as u16 {
                a[j] = d1 as i16;
                j += 1;
            }
            if j < 256 && d2 < Q as u16 {
                a[j] = d2 as i16;
                j += 1;
            }
            off += 3;
        }
    }
    a
}

/// `SampleNTT` ×4: four independent uniform polynomials from four 34-byte
/// seeds, all sampled in lockstep over a shared 4-way SHAKE128. Matches
/// running [`sample_ntt`] four times serially, bit-for-bit; the speedup
/// comes from the underlying NEON 4-way Keccak-f[1600] processing all four
/// streams per permutation (~2.5× total throughput on Apple M-series).
///
/// On non-aarch64 architectures degrades to four serial [`sample_ntt`]
/// calls. The output and rejection-sampling decisions are identical either
/// way — verified by `sample_ntt_x4_matches_serial` below.
///
/// Per-stream rejection means the four streams may need different numbers
/// of squeeze blocks. The loop continues until all four polynomials are
/// filled (`max(blocks_consumed) ≈ E[blocks] + a small tail`, well under 8
/// blocks per stream in practice with `Q = 3329`).
pub fn sample_ntt_x4(seeds: [&[u8]; 4]) -> [[i16; 256]; 4] {
    #[cfg(target_arch = "aarch64")]
    {
        sample_ntt_x4_neon(seeds)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 just runtime-detected.
                return unsafe { sample_ntt_x4_avx2(seeds) };
            }
        }
        [
            sample_ntt(seeds[0]),
            sample_ntt(seeds[1]),
            sample_ntt(seeds[2]),
            sample_ntt(seeds[3]),
        ]
    }
}

/// Per-stream rejection-sampling loop shared between the NEON and AVX2
/// fast paths. The closure produces the next 168-byte block per stream;
/// the inner logic is bit-identical to four serial `sample_ntt` calls
/// because the underlying SHAKE128 byte stream is identical per seed.
fn sample_ntt_x4_with<F>(mut next_block: F) -> [[i16; 256]; 4]
where
    F: FnMut(&mut [[u8; crate::sha3::SHAKE128_RATE]; 4]),
{
    use crate::sha3::SHAKE128_RATE;
    let mut a = [[0i16; 256]; 4];
    let mut j = [0usize; 4];
    let mut bufs = [[0u8; SHAKE128_RATE]; 4];
    while j.iter().any(|&jc| jc < 256) {
        next_block(&mut bufs);
        for s in 0..4 {
            if j[s] >= 256 {
                continue;
            }
            let buf = &bufs[s];
            let mut off = 0;
            while off + 3 <= SHAKE128_RATE && j[s] < 256 {
                let b0 = buf[off] as u16;
                let b1 = buf[off + 1] as u16;
                let b2 = buf[off + 2] as u16;
                let d1 = b0 | ((b1 & 0x0f) << 8);
                let d2 = (b1 >> 4) | (b2 << 4);
                if d1 < Q as u16 {
                    a[s][j[s]] = d1 as i16;
                    j[s] += 1;
                }
                if j[s] < 256 && d2 < Q as u16 {
                    a[s][j[s]] = d2 as i16;
                    j[s] += 1;
                }
                off += 3;
            }
        }
    }
    a
}

#[cfg(target_arch = "aarch64")]
fn sample_ntt_x4_neon(seeds: [&[u8]; 4]) -> [[i16; 256]; 4] {
    use crate::sha3::ShakeState4;
    let mut xof = ShakeState4::absorb_short(seeds);
    sample_ntt_x4_with(move |bufs| xof.next_block(bufs))
}

/// AVX2 path. Caller (the `sample_ntt_x4` dispatcher) has already
/// runtime-detected AVX2.
///
/// # Safety
/// CPU must support AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sample_ntt_x4_avx2(seeds: [&[u8]; 4]) -> [[i16; 256]; 4] {
    use crate::sha3::avx2_x4::ShakeState4Avx2;
    // SAFETY: target_feature(enable = "avx2") on this fn means we may
    // freely call other AVX2-gated routines inside.
    let mut xof = unsafe { ShakeState4Avx2::absorb_short(seeds) };
    sample_ntt_x4_with(move |bufs| {
        // SAFETY: same — we're in an AVX2-enabled function.
        unsafe { xof.next_block(bufs) }
    })
}

/// `PRF_2(s, b)` = SHAKE-256(`s ‖ b`) → 128 bytes (`64·η`, η = 2).
fn prf_eta2(sigma: &[u8; 32], nonce: u8) -> [u8; 128] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(sigma);
    input[32] = nonce;
    let mut out = [0u8; 128];
    sha3::shake256(&input, &mut out);
    out
}

/// `SamplePolyCBD_2` over a 128-byte PRF block: each coefficient is the
/// centered binomial `popcount(2 bits) - popcount(2 bits)` in `[-2, 2]`.
fn cbd2(buf: &[u8; 128]) -> [i16; 256] {
    let mut r = [0i16; 256];
    // 128 bytes = 32 groups of 4 bytes, each yielding 8 coefficients.
    for i in 0..32 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = a - b;
        }
    }
    r
}

/// Sample a centered-binomial noise polynomial (η = 2) from `sigma` and the
/// domain-separating `nonce`.
pub fn sample_cbd_eta2(sigma: &[u8; 32], nonce: u8) -> [i16; 256] {
    cbd2(&prf_eta2(sigma, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_ntt_in_range_and_deterministic() {
        let mut seed = [0u8; 34];
        seed[..32].copy_from_slice(&[0x5a; 32]);
        seed[32] = 1;
        seed[33] = 2;
        let a = sample_ntt(&seed);
        let b = sample_ntt(&seed);
        assert_eq!(a, b, "deterministic");
        assert!(a.iter().all(|&c| (0..Q).contains(&c)), "all in [0,q)");
        // different index → different polynomial
        seed[33] = 3;
        assert_ne!(sample_ntt(&seed), a);
    }

    /// Sanity-check microbenchmark — run with `--release --nocapture` to see
    /// the timing comparison. Not a perf gate (no assert), just a tool for
    /// quantifying the 4-way SIMD win during tuning.
    #[test]
    #[ignore = "informational microbench; opt in with `--ignored --nocapture --release`"]
    fn sample_ntt_x4_speedup_microbench() {
        use std::time::Instant;
        let rho = [0xc3u8; 32];
        let mut seeds_buf = [[0u8; 34]; 4];
        for (k, slot) in seeds_buf.iter_mut().enumerate() {
            slot[..32].copy_from_slice(&rho);
            slot[32] = (k as u8) % 3;
            slot[33] = (k as u8) / 3;
        }
        let seed_refs: [&[u8]; 4] = [
            &seeds_buf[0],
            &seeds_buf[1],
            &seeds_buf[2],
            &seeds_buf[3],
        ];

        // warm
        for _ in 0..50 {
            let _ = sample_ntt_x4(seed_refs);
            for s in &seeds_buf {
                let _ = sample_ntt(s);
            }
        }

        let iters = 1_000u32;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(sample_ntt_x4(seed_refs));
        }
        let x4_per_call_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        let start = Instant::now();
        for _ in 0..iters {
            for s in &seeds_buf {
                let _ = std::hint::black_box(sample_ntt(std::hint::black_box(s)));
            }
        }
        let serial_per_quad_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        eprintln!("sample_ntt_x4 (4 polys / call): {x4_per_call_ns} ns");
        eprintln!("4× sample_ntt serial:           {serial_per_quad_ns} ns");
        eprintln!(
            "  speedup: {:.2}×",
            serial_per_quad_ns as f64 / x4_per_call_ns as f64
        );
    }

    #[test]
    fn sample_ntt_x4_matches_serial() {
        // Four distinct (i,j) cells of a rho-derived matrix, exactly the
        // shape ML-KEM matrix sampling produces.
        let rho = [0xa5u8; 32];
        let mut seeds_buf = [[0u8; 34]; 4];
        let pairs = [(0u8, 0u8), (1, 0), (0, 1), (2, 2)];
        for (slot, &(i, j)) in seeds_buf.iter_mut().zip(pairs.iter()) {
            slot[..32].copy_from_slice(&rho);
            slot[32] = i;
            slot[33] = j;
        }
        let seed_refs: [&[u8]; 4] = [
            &seeds_buf[0],
            &seeds_buf[1],
            &seeds_buf[2],
            &seeds_buf[3],
        ];
        let parallel = sample_ntt_x4(seed_refs);
        for k in 0..4 {
            let serial = sample_ntt(&seeds_buf[k]);
            assert_eq!(parallel[k], serial, "stream {k}");
        }
    }

    #[test]
    fn cbd_in_range_and_centered() {
        let sigma = [0x33u8; 32];
        let p = sample_cbd_eta2(&sigma, 0);
        assert!(p.iter().all(|&c| (-2..=2).contains(&c)), "eta=2 range");
        // deterministic + nonce-separated
        assert_eq!(p, sample_cbd_eta2(&sigma, 0));
        assert_ne!(p, sample_cbd_eta2(&sigma, 1));
        // mean should be near zero over 256 samples
        let sum: i32 = p.iter().map(|&c| c as i32).sum();
        assert!(sum.abs() < 80, "roughly centered, sum={sum}");
    }
}
