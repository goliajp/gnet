//! Polynomial and module-vector arithmetic for ML-KEM-768 (rank `K = 3`),
//! layered on the NTT ([`super::ntt`]). Scaling follows the FIPS 203 / Kyber
//! reference: matrix/vector products are accumulated in the NTT domain (each
//! base multiply carries a `2^-16` Montgomery factor) and corrected with
//! [`to_mont`] or absorbed by [`super::ntt::invntt`].

use super::ntt;
use super::sample::sample_ntt;

/// Module rank for ML-KEM-768.
pub const K: usize = 3;

/// A ring element (256 coefficients).
pub type Poly = [i16; 256];
/// A length-`K` module vector.
pub type PolyVec = [Poly; K];

/// Coefficient-wise add.
pub fn add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| a[i] + b[i])
}

/// Coefficient-wise subtract.
pub fn sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| a[i] - b[i])
}

/// Barrett-reduce every coefficient into `(-q/2, q/2]`.
pub fn reduce(a: &Poly) -> Poly {
    core::array::from_fn(|i| ntt::barrett_reduce(a[i]))
}

/// Multiply every coefficient by `2^16 mod q` (Montgomery `to_mont`): undoes
/// the `2^-16` factor left by one NTT-domain base multiply.
pub fn to_mont(a: &Poly) -> Poly {
    const F: i16 = 1353; // 2^32 mod q
    core::array::from_fn(|i| ntt::fqmul(a[i], F))
}

/// Forward NTT of a polynomial.
pub fn ntt_poly(a: &Poly) -> Poly {
    let mut r = *a;
    ntt::ntt(&mut r);
    r
}

/// Inverse NTT of a polynomial (with the reference's Montgomery scaling).
pub fn invntt_poly(a: &Poly) -> Poly {
    let mut r = *a;
    ntt::invntt(&mut r);
    r
}

/// NTT of each component of a module vector.
pub fn polyvec_ntt(v: &PolyVec) -> PolyVec {
    core::array::from_fn(|i| ntt_poly(&v[i]))
}

/// `Σ_j a[j] ∘ b[j]` in the NTT domain (base multiply + accumulate). The
/// result still carries a single `2^-16` factor — the caller applies
/// [`to_mont`] or an inverse NTT.
pub fn dot(a: &PolyVec, b: &PolyVec) -> Poly {
    let mut acc = ntt::ntt_mul(&a[0], &b[0]);
    for j in 1..K {
        let t = ntt::ntt_mul(&a[j], &b[j]);
        acc = add(&acc, &t);
    }
    acc
}

/// Generate the public matrix `Â` (NTT domain) from the 32-byte seed `rho`.
/// `transposed` selects the `(i,j)` byte order: KeyGen uses `Â`, Encrypt uses
/// `Â^T`, matching the FIPS 203 reference.
pub fn gen_matrix(rho: &[u8; 32], transposed: bool) -> [PolyVec; K] {
    core::array::from_fn(|i| {
        core::array::from_fn(|j| {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            if transposed {
                seed[32] = i as u8;
                seed[33] = j as u8;
            } else {
                seed[32] = j as u8;
                seed[33] = i as u8;
            }
            sample_ntt(&seed)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::ntt::Q;
    use super::*;

    #[test]
    fn add_sub_inverse() {
        let a: Poly = core::array::from_fn(|i| (i as i16) % Q);
        let b: Poly = core::array::from_fn(|i| (3 * i as i16) % Q);
        let s = add(&a, &b);
        let d = sub(&s, &b);
        for i in 0..256 {
            assert_eq!(d[i], a[i]);
        }
    }

    #[test]
    fn matrix_is_transpose() {
        let rho = [0x11u8; 32];
        let a = gen_matrix(&rho, false);
        let at = gen_matrix(&rho, true);
        // at[i][j] must equal a[j][i]
        for i in 0..K {
            for j in 0..K {
                assert_eq!(at[i][j], a[j][i], "({i},{j})");
            }
        }
    }
}
