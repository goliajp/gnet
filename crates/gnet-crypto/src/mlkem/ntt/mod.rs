//! Number-theoretic transform over `Z_q[X]/(X^256 + 1)`, `q = 3329`, the ring
//! ML-KEM (FIPS 203) operates in. Coefficients are signed 16-bit; arithmetic
//! uses Montgomery and Barrett reduction (constants from the FIPS 203 / Kyber
//! reference). The transform is the "incomplete" 7-layer NTT: the ring splits
//! into 128 degree-2 factors, so multiplication in the NTT domain is a
//! per-pair [`basemul`].
//!
//! On aarch64 the 5 outermost butterfly layers (`len` = 128, 64, 32, 16, 8)
//! run via NEON 8-way `int16x8_t` SIMD; the two innermost layers (`len` =
//! 4, 2) plus base multiplications stay scalar. The 5 SIMD layers do
//! 5 × 128 = 640 of the 7 × 128 = 896 butterflies, ~71% of the total
//! arithmetic work. KAT preservation is automatic — the NEON path branches
//! on `cfg(target_arch = "aarch64")` and produces the identical i16 stream
//! lane-for-lane (verified by `ntt_neon_matches_scalar` below).

/// The ML-KEM modulus.
pub const Q: i16 = 3329;

/// `q^{-1} mod 2^16` (signed), for Montgomery reduction.
const QINV: i16 = -3327;

/// Powers of the primitive 256-th root ζ = 17, in bit-reversed order and
/// Montgomery form (`ζ^i · 2^16 mod q`). Indices 1.. drive the NTT layers;
/// 64.. drive [`basemul`]. Verbatim from the FIPS 203 reference.
const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Montgomery reduction: for `|a| < q·2^15`, returns `a·2^-16 mod q` in
/// `(-q, q)`.
#[inline(always)]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV) as i32;
    ((a - t * Q as i32) >> 16) as i16
}

/// Barrett reduction: returns a representative of `a mod q` in `(-q/2, q/2]`.
#[inline(always)]
pub fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159; // ⌊2^26 / q⌉
    let t = ((V * a as i32 + (1 << 25)) >> 26) as i16;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Montgomery multiply: `a·b·2^-16 mod q`.
#[inline(always)]
pub fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// In-place forward NTT (normal → NTT domain). Output coefficients are
/// congruent mod q but not fully reduced; callers reduce as needed.
pub fn ntt(r: &mut [i16; 256]) {
    #[cfg(target_arch = "aarch64")]
    {
        ntt_neon(r);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 just runtime-detected.
            unsafe {
                avx2::ntt_avx2(r);
            }
            return;
        }
        ntt_scalar(r);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        ntt_scalar(r);
    }
}

/// In-place inverse NTT (NTT → normal domain), including the `2^16/128`
/// Montgomery-corrected scaling so that `invntt(basemul(ntt a, ntt b))` is
/// `a·b mod (X^256+1)` in the normal domain.
pub fn invntt(r: &mut [i16; 256]) {
    #[cfg(target_arch = "aarch64")]
    {
        invntt_neon(r);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 just runtime-detected.
            unsafe {
                avx2::invntt_avx2(r);
            }
            return;
        }
        invntt_scalar(r);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        invntt_scalar(r);
    }
}

/// Scalar reference NTT — always-correct fallback used on non-aarch64 and
/// referenced by `ntt_neon_matches_scalar` to validate the SIMD path.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn ntt_scalar(r: &mut [i16; 256]) {
    let mut k = 1usize;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Scalar reference inverse NTT — always-correct fallback.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn invntt_scalar(r: &mut [i16; 256]) {
    const F: i16 = 1441; // 2^32 / 128 mod q
    let mut k = 127usize;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] -= t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in r.iter_mut() {
        *c = fqmul(*c, F);
    }
}

#[cfg(target_arch = "aarch64")]
mod neon;

#[cfg(target_arch = "aarch64")]
use neon::{invntt_neon, ntt_mul_into_neon, ntt_neon};

#[cfg(target_arch = "x86_64")]
mod avx2;

/// Multiply two degree-1 polynomials in `Z_q[X]/(X^2 - zeta)` (one NTT pair).
#[inline(always)]
fn basemul(a: &[i16; 2], b: &[i16; 2], zeta: i16) -> [i16; 2] {
    [
        fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0]),
        fqmul(a[0], b[1]) + fqmul(a[1], b[0]),
    ]
}

/// Pointwise multiplication in the NTT domain into a caller-provided
/// polynomial: 128 degree-2 base multiplies. No allocation, no return-by-
/// value copy of 512-byte arrays.
#[inline]
pub fn ntt_mul_into(a: &[i16; 256], b: &[i16; 256], r: &mut [i16; 256]) {
    #[cfg(target_arch = "aarch64")]
    {
        ntt_mul_into_neon(a, b, r);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        ntt_mul_into_scalar(a, b, r);
    }
}

/// Scalar reference base multiplication — always-correct fallback.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn ntt_mul_into_scalar(a: &[i16; 256], b: &[i16; 256], r: &mut [i16; 256]) {
    for i in 0..64 {
        let z = ZETAS[64 + i];
        let lo = basemul(&[a[4 * i], a[4 * i + 1]], &[b[4 * i], b[4 * i + 1]], z);
        let hi = basemul(
            &[a[4 * i + 2], a[4 * i + 3]],
            &[b[4 * i + 2], b[4 * i + 3]],
            -z,
        );
        r[4 * i] = lo[0];
        r[4 * i + 1] = lo[1];
        r[4 * i + 2] = hi[0];
        r[4 * i + 3] = hi[1];
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn norm(x: i16) -> i16 {
        x.rem_euclid(Q)
    }

    /// Schoolbook multiply in `Z_q[X]/(X^256 + 1)` (X^256 = -1).
    fn schoolbook(a: &[i16; 256], b: &[i16; 256]) -> [i16; 256] {
        let mut c = [0i32; 256];
        for i in 0..256 {
            for j in 0..256 {
                let p = a[i] as i32 * b[j] as i32;
                if i + j < 256 {
                    c[i + j] += p;
                } else {
                    c[i + j - 256] -= p;
                }
            }
        }
        core::array::from_fn(|i| c[i].rem_euclid(Q as i32) as i16)
    }

    fn sample(seed: u64) -> [i16; 256] {
        let mut s = seed;
        core::array::from_fn(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) as i16 % Q
        })
    }

    /// The strong KAT: NTT-domain multiply must equal the schoolbook product
    /// in `Z_q[X]/(X^256+1)`. This pins ZETAS + both reductions + ntt + invntt
    /// + basemul + the final scaling together.
    #[test]
    fn ntt_mul_matches_schoolbook() {
        for seed in 0..16u64 {
            let a = sample(seed);
            let b = sample(seed.wrapping_add(0xabcd));
            let mut na = a;
            let mut nb = b;
            ntt(&mut na);
            ntt(&mut nb);
            let mut prod = [0i16; 256];
            ntt_mul_into(&na, &nb, &mut prod);
            invntt(&mut prod);

            let want = schoolbook(&a, &b);
            for i in 0..256 {
                assert_eq!(norm(prod[i]), norm(want[i]), "seed {seed} coeff {i}");
            }
        }
    }

    /// On x86_64 with AVX2 the AVX2 forward / inverse NTT must match the
    /// scalar reference on every coefficient — same contract as
    /// `ntt_neon_matches_scalar` for the aarch64 path. Skipped at runtime
    /// on x86_64 hosts without AVX2 (the dispatch falls back to scalar
    /// anyway, so there's nothing to verify against itself).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ntt_avx2_matches_scalar() {
        if !std::is_x86_feature_detected!("avx2") {
            eprintln!("skipping: host has no AVX2");
            return;
        }
        for seed in 0..32u64 {
            let a = sample(seed);

            let mut avx2_fwd = a;
            // SAFETY: AVX2 just detected.
            unsafe { super::avx2::ntt_avx2(&mut avx2_fwd) };
            let mut scalar_fwd = a;
            super::ntt_scalar(&mut scalar_fwd);
            assert_eq!(avx2_fwd, scalar_fwd, "fwd ntt seed {seed}");

            let mut avx2_inv = avx2_fwd;
            // SAFETY: AVX2 just detected.
            unsafe { super::avx2::invntt_avx2(&mut avx2_inv) };
            let mut scalar_inv = scalar_fwd;
            super::invntt_scalar(&mut scalar_inv);
            assert_eq!(avx2_inv, scalar_inv, "inv ntt seed {seed}");
        }
    }

    /// On aarch64 the NEON `ntt_neon` / `invntt_neon` outputs must match
    /// the scalar reference on every coefficient, for every input — this
    /// is the contract that lets us swap them at the public-fn level.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn ntt_neon_matches_scalar() {
        for seed in 0..32u64 {
            let a = sample(seed);

            let mut neon_fwd = a;
            super::ntt(&mut neon_fwd);
            let mut scalar_fwd = a;
            super::ntt_scalar(&mut scalar_fwd);
            assert_eq!(neon_fwd, scalar_fwd, "fwd ntt seed {seed}");

            let mut neon_inv = neon_fwd;
            super::invntt(&mut neon_inv);
            let mut scalar_inv = scalar_fwd;
            super::invntt_scalar(&mut scalar_inv);
            assert_eq!(neon_inv, scalar_inv, "inv ntt seed {seed}");
        }
    }

    /// The NEON `ntt_mul_into_neon` must produce the exact same output as
    /// the scalar reference, lane-for-lane, for any inputs.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn ntt_mul_neon_matches_scalar() {
        for seed in 0..32u64 {
            let a = sample(seed);
            let b = sample(seed.wrapping_add(0x9e37));
            // NTT-domain inputs (ntt_mul expects NTT-domain operands).
            let mut na = a;
            super::ntt(&mut na);
            let mut nb = b;
            super::ntt(&mut nb);

            let mut neon_r = [0i16; 256];
            super::ntt_mul_into(&na, &nb, &mut neon_r);
            let mut scalar_r = [0i16; 256];
            super::ntt_mul_into_scalar(&na, &nb, &mut scalar_r);
            assert_eq!(neon_r, scalar_r, "seed {seed}");
        }
    }

    /// Informational microbench — compare ntt_mul NEON vs scalar.
    #[cfg(target_arch = "aarch64")]
    #[test]
    #[ignore = "informational microbench"]
    fn ntt_mul_speedup_microbench() {
        use std::time::Instant;
        let a = sample(7);
        let b = sample(11);
        let mut na = a;
        super::ntt(&mut na);
        let mut nb = b;
        super::ntt(&mut nb);

        // warm
        for _ in 0..500 {
            let mut r = [0i16; 256];
            super::ntt_mul_into(&na, &nb, &mut r);
            super::ntt_mul_into_scalar(&na, &nb, &mut r);
        }

        let iters = 20_000u32;

        let start = Instant::now();
        for _ in 0..iters {
            let mut r = [0i16; 256];
            super::ntt_mul_into(
                std::hint::black_box(&na),
                std::hint::black_box(&nb),
                std::hint::black_box(&mut r),
            );
        }
        let neon_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        let start = Instant::now();
        for _ in 0..iters {
            let mut r = [0i16; 256];
            super::ntt_mul_into_scalar(
                std::hint::black_box(&na),
                std::hint::black_box(&nb),
                std::hint::black_box(&mut r),
            );
        }
        let scalar_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        eprintln!(
            "ntt_mul_into NEON: {neon_ns} ns  scalar: {scalar_ns} ns  speedup {:.2}×",
            scalar_ns as f64 / neon_ns as f64
        );
    }

    /// Informational microbench — compare per-call wall time of the NEON
    /// NTT vs the scalar reference. Run with
    ///   `cargo test --release -p gnet-crypto --lib mlkem::ntt::tests::ntt_speedup_microbench -- --ignored --nocapture`.
    #[cfg(target_arch = "aarch64")]
    #[test]
    #[ignore = "informational microbench"]
    fn ntt_speedup_microbench() {
        use std::time::Instant;
        let a = sample(42);

        // warm
        for _ in 0..100 {
            let mut r = a;
            super::ntt(&mut r);
            super::invntt(&mut r);
            let mut r2 = a;
            super::ntt_scalar(&mut r2);
            super::invntt_scalar(&mut r2);
        }

        let iters = 10_000u32;

        let start = Instant::now();
        for _ in 0..iters {
            let mut r = std::hint::black_box(a);
            super::ntt(&mut r);
            std::hint::black_box(&r);
        }
        let neon_fwd_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        let start = Instant::now();
        for _ in 0..iters {
            let mut r = std::hint::black_box(a);
            super::ntt_scalar(&mut r);
            std::hint::black_box(&r);
        }
        let scalar_fwd_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        let mut na = a;
        super::ntt(&mut na);
        let start = Instant::now();
        for _ in 0..iters {
            let mut r = std::hint::black_box(na);
            super::invntt(&mut r);
            std::hint::black_box(&r);
        }
        let neon_inv_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        let start = Instant::now();
        for _ in 0..iters {
            let mut r = std::hint::black_box(na);
            super::invntt_scalar(&mut r);
            std::hint::black_box(&r);
        }
        let scalar_inv_ns = start.elapsed().as_nanos() as u64 / iters as u64;

        eprintln!("ntt    NEON: {neon_fwd_ns} ns  scalar: {scalar_fwd_ns} ns  speedup {:.2}×",
            scalar_fwd_ns as f64 / neon_fwd_ns as f64);
        eprintln!("invntt NEON: {neon_inv_ns} ns  scalar: {scalar_inv_ns} ns  speedup {:.2}×",
            scalar_inv_ns as f64 / neon_inv_ns as f64);
    }

    /// invntt(ntt(a)) = a · 2^16 mod q (Montgomery factor); stripping it
    /// recovers a.
    #[test]
    fn ntt_roundtrip() {
        let a = sample(7);
        let mut r = a;
        ntt(&mut r);
        invntt(&mut r);
        for i in 0..256 {
            assert_eq!(
                norm(montgomery_reduce(r[i] as i32)),
                norm(a[i]),
                "coeff {i}"
            );
        }
    }
}
