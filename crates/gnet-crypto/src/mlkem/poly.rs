//! Polynomial and module-vector arithmetic for ML-KEM-768 (rank `K = 3`),
//! layered on the NTT ([`super::ntt`]). Scaling follows the FIPS 203 / Kyber
//! reference: matrix/vector products are accumulated in the NTT domain (each
//! base multiply carries a `2^-16` Montgomery factor) and corrected with
//! [`to_mont`] or absorbed by [`super::ntt::invntt`].
//!
//! The in-place variants (`add_in_place`, `dot_into`, `polyvec_ntt_in_place`,
//! …) are the hot path; the returning variants are convenience wrappers used
//! by tests and the historical API.

use super::ntt;
use super::sample::sample_ntt;

/// Module rank for ML-KEM-768.
pub const K: usize = 3;

/// A ring element (256 coefficients).
pub type Poly = [i16; 256];
/// A length-`K` module vector.
pub type PolyVec = [Poly; K];

/// Coefficient-wise add (in place): `a += b`.
#[inline]
pub fn add_in_place(a: &mut Poly, b: &Poly) {
    for i in 0..256 {
        a[i] = a[i].wrapping_add(b[i]);
    }
}

/// Coefficient-wise sub (in place): `a -= b`.
#[inline]
pub fn sub_in_place(a: &mut Poly, b: &Poly) {
    for i in 0..256 {
        a[i] = a[i].wrapping_sub(b[i]);
    }
}

/// Barrett-reduce every coefficient into `(-q/2, q/2]` (in place).
#[inline]
pub fn reduce_in_place(a: &mut Poly) {
    for c in a.iter_mut() {
        *c = ntt::barrett_reduce(*c);
    }
}

/// Multiply every coefficient by `2^16 mod q` (in place): undoes the `2^-16`
/// factor left by one NTT-domain base multiply.
#[inline]
pub fn to_mont_in_place(a: &mut Poly) {
    const F: i16 = 1353; // 2^32 mod q
    for c in a.iter_mut() {
        *c = ntt::fqmul(*c, F);
    }
}

/// NTT of each component of a module vector (in place).
#[inline]
pub fn polyvec_ntt_in_place(v: &mut PolyVec) {
    for poly in v.iter_mut() {
        ntt::ntt(poly);
    }
}

/// `Σ_j a[j] ∘ b[j]` in the NTT domain (base multiply + accumulate) into a
/// caller-provided polynomial. Result carries a single `2^-16` factor — the
/// caller applies [`to_mont_in_place`] or [`ntt::invntt`].
#[inline]
pub fn dot_into(a: &PolyVec, b: &PolyVec, out: &mut Poly) {
    ntt::ntt_mul_into(&a[0], &b[0], out);
    let mut tmp = [0i16; 256];
    for j in 1..K {
        ntt::ntt_mul_into(&a[j], &b[j], &mut tmp);
        add_in_place(out, &tmp);
    }
}

/// Generate the public matrix `Â` (NTT domain) from the 32-byte seed `rho`.
/// `transposed` selects the `(i,j)` byte order: KeyGen uses `Â`, Encrypt uses
/// `Â^T`, matching the FIPS 203 reference.
pub fn gen_matrix(rho: &[u8; 32], transposed: bool) -> [PolyVec; K] {
    let mut out: [PolyVec; K] = [[[0i16; 256]; K]; K];
    for (i, row) in out.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            if transposed {
                seed[32] = i as u8;
                seed[33] = j as u8;
            } else {
                seed[32] = j as u8;
                seed[33] = i as u8;
            }
            *cell = sample_ntt(&seed);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::ntt::Q;
    use super::*;

    #[test]
    fn add_sub_inverse() {
        let a: Poly = core::array::from_fn(|i| (i as i16) % Q);
        let b: Poly = core::array::from_fn(|i| (3 * i as i16) % Q);
        let mut s = a;
        add_in_place(&mut s, &b);
        let mut d = s;
        sub_in_place(&mut d, &b);
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

    /// In-place variants must match a reference computed via wrapping ops
    /// on plain integers.
    #[test]
    fn in_place_arithmetic_is_correct() {
        let a: Poly = core::array::from_fn(|i| (i as i16) % Q);
        let b: Poly = core::array::from_fn(|i| ((i * 7 + 3) as i16) % Q);

        let mut x = a;
        add_in_place(&mut x, &b);
        for i in 0..256 {
            assert_eq!(x[i], a[i].wrapping_add(b[i]));
        }

        let mut x = a;
        sub_in_place(&mut x, &b);
        for i in 0..256 {
            assert_eq!(x[i], a[i].wrapping_sub(b[i]));
        }

        let mut x = a;
        reduce_in_place(&mut x);
        for i in 0..256 {
            assert_eq!(x[i], ntt::barrett_reduce(a[i]));
        }

        let mut x = a;
        to_mont_in_place(&mut x);
        const F: i16 = 1353;
        for i in 0..256 {
            assert_eq!(x[i], ntt::fqmul(a[i], F));
        }
    }

    /// `dot_into` accumulates `Σ a[j] ∘ b[j]` consistently with separate
    /// ntt_mul + add steps.
    #[test]
    fn dot_into_is_sum_of_mul() {
        let rho = [0x33u8; 32];
        let m = gen_matrix(&rho, false);
        let v: PolyVec = [
            core::array::from_fn(|i| (i as i16) % Q),
            core::array::from_fn(|i| ((i * 3) as i16) % Q),
            core::array::from_fn(|i| ((i * 5) as i16) % Q),
        ];
        let mut got = [0i16; 256];
        dot_into(&m[0], &v, &mut got);

        let mut want = [0i16; 256];
        ntt::ntt_mul_into(&m[0][0], &v[0], &mut want);
        let mut tmp = [0i16; 256];
        for j in 1..K {
            ntt::ntt_mul_into(&m[0][j], &v[j], &mut tmp);
            for k in 0..256 {
                want[k] = want[k].wrapping_add(tmp[k]);
            }
        }
        assert_eq!(got, want);
    }
}
