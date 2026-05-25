//! K-PKE, the IND-CPA public-key scheme underlying ML-KEM-768 (FIPS 203
//! §5). Key generation, encryption, and decryption over the module lattice,
//! with FIPS 203 serialization. Parameters: `K = 3`, `du = 10`, `dv = 4`,
//! `η = 2`.

use super::poly::{
    K, Poly, PolyVec, add, dot, gen_matrix, invntt_poly, polyvec_ntt, reduce, sub, to_mont,
};
use super::sample::sample_cbd_eta2;
use super::serialize::{byte_decode, byte_encode, compress, decompress, freeze};
use crate::sha3::sha3_512;

/// Compression width for the ciphertext vector `u`.
const DU: usize = 10;
/// Compression width for the ciphertext polynomial `v`.
const DV: usize = 4;
/// Bytes of a single ByteEncode_12 polynomial.
const POLY12: usize = 384;

/// Encoded K-PKE encryption key length (`384·K + 32`).
pub const EK_LEN: usize = POLY12 * K + 32;
/// Encoded K-PKE decryption key length (`384·K`).
pub const DK_LEN: usize = POLY12 * K;
/// Ciphertext length (`32·du·K + 32·dv`).
pub const CT_LEN: usize = 32 * DU * K + 32 * DV;

/// ByteEncode_12 of an NTT-domain module vector.
fn encode_pv12(v: &PolyVec) -> Vec<u8> {
    let mut out = vec![0u8; POLY12 * K];
    for i in 0..K {
        let c: [u16; 256] = core::array::from_fn(|j| freeze(v[i][j]));
        byte_encode(12, &c, &mut out[i * POLY12..(i + 1) * POLY12]);
    }
    out
}

/// ByteDecode_12 into an NTT-domain module vector.
fn decode_pv12(bytes: &[u8]) -> PolyVec {
    core::array::from_fn(|i| {
        let c = byte_decode(12, &bytes[i * POLY12..(i + 1) * POLY12]);
        core::array::from_fn(|j| c[j] as i16)
    })
}

/// Compress_d then ByteEncode_d of a module vector.
fn compress_encode_pv(v: &PolyVec, d: usize) -> Vec<u8> {
    let bytes = 32 * d;
    let mut out = vec![0u8; bytes * K];
    for i in 0..K {
        let c: [u16; 256] = core::array::from_fn(|j| compress(d as u32, freeze(v[i][j])));
        byte_encode(d, &c, &mut out[i * bytes..(i + 1) * bytes]);
    }
    out
}

/// ByteDecode_d then Decompress_d of a module vector.
fn decode_decompress_pv(data: &[u8], d: usize) -> PolyVec {
    let bytes = 32 * d;
    core::array::from_fn(|i| {
        let c = byte_decode(d, &data[i * bytes..(i + 1) * bytes]);
        core::array::from_fn(|j| decompress(d as u32, c[j]) as i16)
    })
}

/// Compress_d then ByteEncode_d of a polynomial.
fn compress_encode_poly(p: &Poly, d: usize) -> Vec<u8> {
    let mut out = vec![0u8; 32 * d];
    let c: [u16; 256] = core::array::from_fn(|j| compress(d as u32, freeze(p[j])));
    byte_encode(d, &c, &mut out);
    out
}

/// ByteDecode_d then Decompress_d of a polynomial.
fn decode_decompress_poly(data: &[u8], d: usize) -> Poly {
    let c = byte_decode(d, data);
    core::array::from_fn(|j| decompress(d as u32, c[j]) as i16)
}

/// Decompress_1 ∘ ByteDecode_1: a 32-byte message to its `{0, ⌈q/2⌋}` poly.
fn poly_frommsg(m: &[u8; 32]) -> Poly {
    let bits = byte_decode(1, m);
    core::array::from_fn(|i| decompress(1, bits[i]) as i16)
}

/// Compress_1 ∘ ByteEncode_1: a poly back to its 32-byte message bits.
fn poly_tomsg(p: &Poly) -> [u8; 32] {
    let bits: [u16; 256] = core::array::from_fn(|i| compress(1, freeze(p[i])));
    let mut m = [0u8; 32];
    byte_encode(1, &bits, &mut m);
    m
}

/// K-PKE.KeyGen (Alg 13): expand `d` into a key pair `(ek, dk)`.
pub fn keygen(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut g_in = [0u8; 33];
    g_in[..32].copy_from_slice(d);
    g_in[32] = K as u8;
    let g = sha3_512(&g_in);
    let rho: [u8; 32] = g[..32].try_into().unwrap();
    let sigma: [u8; 32] = g[32..].try_into().unwrap();

    let a = gen_matrix(&rho, false);
    let s: PolyVec = core::array::from_fn(|i| sample_cbd_eta2(&sigma, i as u8));
    let e: PolyVec = core::array::from_fn(|i| sample_cbd_eta2(&sigma, (K + i) as u8));
    let s_hat = polyvec_ntt(&s);
    let e_hat = polyvec_ntt(&e);

    let t: PolyVec = core::array::from_fn(|i| {
        let acc = to_mont(&dot(&a[i], &s_hat));
        reduce(&add(&acc, &e_hat[i]))
    });

    let mut ek = encode_pv12(&t);
    ek.extend_from_slice(&rho);
    let dk = encode_pv12(&s_hat);
    (ek, dk)
}

/// K-PKE.Encrypt (Alg 14): encrypt the 32-byte `m` under `ek` with `coins`.
pub fn encrypt(ek: &[u8], m: &[u8; 32], coins: &[u8; 32]) -> Vec<u8> {
    let t = decode_pv12(&ek[..POLY12 * K]);
    let rho: [u8; 32] = ek[POLY12 * K..POLY12 * K + 32].try_into().unwrap();
    let at = gen_matrix(&rho, true);

    let r: PolyVec = core::array::from_fn(|i| sample_cbd_eta2(coins, i as u8));
    let e1: PolyVec = core::array::from_fn(|i| sample_cbd_eta2(coins, (K + i) as u8));
    let e2 = sample_cbd_eta2(coins, (2 * K) as u8);
    let r_hat = polyvec_ntt(&r);

    let u: PolyVec = core::array::from_fn(|i| {
        let acc = invntt_poly(&dot(&at[i], &r_hat));
        reduce(&add(&acc, &e1[i]))
    });

    let mu = poly_frommsg(m);
    let tr = invntt_poly(&dot(&t, &r_hat));
    let v = reduce(&add(&add(&tr, &e2), &mu));

    let mut ct = compress_encode_pv(&u, DU);
    ct.extend_from_slice(&compress_encode_poly(&v, DV));
    ct
}

/// K-PKE.Decrypt (Alg 15): recover the 32-byte message from `ct` under `dk`.
pub fn decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let c1 = 32 * DU * K;
    let u = decode_decompress_pv(&ct[..c1], DU);
    let v = decode_decompress_poly(&ct[c1..], DV);
    let s_hat = decode_pv12(dk);

    let su = invntt_poly(&dot(&s_hat, &polyvec_ntt(&u)));
    let w = reduce(&sub(&v, &su));
    poly_tomsg(&w)
}
