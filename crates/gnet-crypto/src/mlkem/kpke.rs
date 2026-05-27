//! K-PKE, the IND-CPA public-key scheme underlying ML-KEM-768 (FIPS 203
//! §5). Key generation, encryption, and decryption over the module lattice,
//! with FIPS 203 serialization. Parameters: `K = 3`, `du = 10`, `dv = 4`,
//! `η = 2`.
//!
//! The hot path is allocation-tight: each top-level call writes its output
//! into a single exactly-sized `Vec`, and intermediate polynomial/vector
//! arithmetic uses the in-place ops in [`super::poly`].

use super::ntt;
use super::poly::{
    K, Poly, PolyVec, add_in_place, dot_into, gen_matrix, polyvec_ntt_in_place, reduce_in_place,
    sub_in_place, to_mont_in_place,
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

/// ByteEncode_12 of an NTT-domain module vector into a caller-provided slice.
fn encode_pv12_into(v: &PolyVec, out: &mut [u8]) {
    debug_assert_eq!(out.len(), POLY12 * K);
    for i in 0..K {
        let c: [u16; 256] = core::array::from_fn(|j| freeze(v[i][j]));
        byte_encode(12, &c, &mut out[i * POLY12..(i + 1) * POLY12]);
    }
}

/// ByteDecode_12 into an NTT-domain module vector.
fn decode_pv12(bytes: &[u8]) -> PolyVec {
    let mut v: PolyVec = [[0i16; 256]; K];
    for i in 0..K {
        let c = byte_decode(12, &bytes[i * POLY12..(i + 1) * POLY12]);
        for j in 0..256 {
            v[i][j] = c[j] as i16;
        }
    }
    v
}

/// Compress_d then ByteEncode_d of a module vector into a caller-provided
/// slice (length `32 * d * K`).
fn compress_encode_pv_into(v: &PolyVec, d: usize, out: &mut [u8]) {
    let bytes = 32 * d;
    debug_assert_eq!(out.len(), bytes * K);
    for i in 0..K {
        let c: [u16; 256] = core::array::from_fn(|j| compress(d as u32, freeze(v[i][j])));
        byte_encode(d, &c, &mut out[i * bytes..(i + 1) * bytes]);
    }
}

/// ByteDecode_d then Decompress_d of a module vector.
fn decode_decompress_pv(data: &[u8], d: usize) -> PolyVec {
    let bytes = 32 * d;
    let mut v: PolyVec = [[0i16; 256]; K];
    for i in 0..K {
        let c = byte_decode(d, &data[i * bytes..(i + 1) * bytes]);
        for j in 0..256 {
            v[i][j] = decompress(d as u32, c[j]) as i16;
        }
    }
    v
}

/// Compress_d then ByteEncode_d of a polynomial into a caller-provided slice.
fn compress_encode_poly_into(p: &Poly, d: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d);
    let c: [u16; 256] = core::array::from_fn(|j| compress(d as u32, freeze(p[j])));
    byte_encode(d, &c, out);
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
    let mut s: PolyVec = [[0i16; 256]; K];
    let mut e: PolyVec = [[0i16; 256]; K];
    for i in 0..K {
        s[i] = sample_cbd_eta2(&sigma, i as u8);
        e[i] = sample_cbd_eta2(&sigma, (K + i) as u8);
    }
    polyvec_ntt_in_place(&mut s);
    polyvec_ntt_in_place(&mut e);

    // t[i] = A[i] · s + e[i], with the Montgomery factor undone via to_mont.
    let mut t: PolyVec = [[0i16; 256]; K];
    for i in 0..K {
        dot_into(&a[i], &s, &mut t[i]);
        to_mont_in_place(&mut t[i]);
        add_in_place(&mut t[i], &e[i]);
        reduce_in_place(&mut t[i]);
    }

    let mut ek = vec![0u8; EK_LEN];
    encode_pv12_into(&t, &mut ek[..POLY12 * K]);
    ek[POLY12 * K..].copy_from_slice(&rho);

    let mut dk = vec![0u8; DK_LEN];
    encode_pv12_into(&s, &mut dk);
    (ek, dk)
}

/// K-PKE.Encrypt (Alg 14): encrypt the 32-byte `m` under `ek` with `coins`.
pub fn encrypt(ek: &[u8], m: &[u8; 32], coins: &[u8; 32]) -> Vec<u8> {
    let t = decode_pv12(&ek[..POLY12 * K]);
    let rho: [u8; 32] = ek[POLY12 * K..POLY12 * K + 32].try_into().unwrap();
    let at = gen_matrix(&rho, true);

    let mut r: PolyVec = [[0i16; 256]; K];
    let mut e1: PolyVec = [[0i16; 256]; K];
    for i in 0..K {
        r[i] = sample_cbd_eta2(coins, i as u8);
        e1[i] = sample_cbd_eta2(coins, (K + i) as u8);
    }
    let e2 = sample_cbd_eta2(coins, (2 * K) as u8);
    polyvec_ntt_in_place(&mut r);

    // u[i] = invntt(A^T[i] · r) + e1[i], then Barrett-reduce.
    let mut u: PolyVec = [[0i16; 256]; K];
    for i in 0..K {
        dot_into(&at[i], &r, &mut u[i]);
        ntt::invntt(&mut u[i]);
        add_in_place(&mut u[i], &e1[i]);
        reduce_in_place(&mut u[i]);
    }

    // v = invntt(t · r) + e2 + mu, Barrett-reduced.
    let mu = poly_frommsg(m);
    let mut v = [0i16; 256];
    dot_into(&t, &r, &mut v);
    ntt::invntt(&mut v);
    add_in_place(&mut v, &e2);
    add_in_place(&mut v, &mu);
    reduce_in_place(&mut v);

    let mut ct = vec![0u8; CT_LEN];
    let c1 = 32 * DU * K;
    compress_encode_pv_into(&u, DU, &mut ct[..c1]);
    compress_encode_poly_into(&v, DV, &mut ct[c1..]);
    ct
}

/// K-PKE.Decrypt (Alg 15): recover the 32-byte message from `ct` under `dk`.
pub fn decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let c1 = 32 * DU * K;
    let mut u = decode_decompress_pv(&ct[..c1], DU);
    let v = decode_decompress_poly(&ct[c1..], DV);
    let s_hat = decode_pv12(dk);

    polyvec_ntt_in_place(&mut u);

    // w = v - invntt(s_hat · u), Barrett-reduced.
    let mut w = [0i16; 256];
    dot_into(&s_hat, &u, &mut w);
    ntt::invntt(&mut w);
    // sub_in_place(target=w, b=...) does target -= b. We want w = v - su, so
    // start from v and subtract w (the su we just computed) into a fresh
    // buffer.
    let mut out = v;
    sub_in_place(&mut out, &w);
    reduce_in_place(&mut out);
    poly_tomsg(&out)
}
