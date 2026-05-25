//! ML-KEM (FIPS 203) sampling: `SampleNTT` (Algorithm 7, rejection sampling of
//! a uniform NTT-domain polynomial from a SHAKE-128 stream) and `SamplePolyCBD`
//! (Algorithm 8, the centered binomial noise) with its SHAKE-256 PRF. ML-KEM-768
//! uses η = 2 throughout.

use super::ntt::Q;
use crate::sha3::{self, Xof};

/// `SampleNTT`: a uniform polynomial in the NTT domain from a 34-byte seed
/// (`ρ ‖ i ‖ j`), via rejection sampling of 12-bit values from SHAKE-128.
pub fn sample_ntt(seed: &[u8]) -> [i16; 256] {
    let mut xof = Xof::shake128(seed);
    let mut a = [0i16; 256];
    let mut j = 0usize;
    let mut buf = [0u8; 3];
    while j < 256 {
        xof.squeeze(&mut buf);
        let d1 = (buf[0] as u16) | (((buf[1] & 0x0f) as u16) << 8);
        let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);
        if d1 < Q as u16 {
            a[j] = d1 as i16;
            j += 1;
        }
        if j < 256 && d2 < Q as u16 {
            a[j] = d2 as i16;
            j += 1;
        }
    }
    a
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
