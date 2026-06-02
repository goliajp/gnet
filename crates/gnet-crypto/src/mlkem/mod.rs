//! ML-KEM-768 (FIPS 203) — the post-quantum key-encapsulation mechanism for
//! the gnet hybrid handshake. Built bottom-up on `ntt` (ring arithmetic),
//! `serialize`/`sample`, `kpke` (the IND-CPA scheme), and [`crate::sha3`].
//!
//! Like the Noise handshake, the API is randomness-injected (the caller passes
//! the 32-byte secrets `d`, `z`, `m`), keeping this crate free of an RNG
//! dependency. The ring math is pinned by the schoolbook KAT in `ntt` and
//! the hashing by the FIPS 202 KATs in [`crate::sha3`]. The full KEM is
//! validated against the official NIST FIPS 203 ACVP known-answer vectors
//! (keyGen / encaps / decaps for ML-KEM-768) in `tests/mlkem_acvp.rs`, plus an
//! encaps/decaps round-trip and implicit-rejection test below.

mod kpke;
mod ntt;
mod poly;
mod sample;
mod serialize;

use crate::sha3::{sha3_256, sha3_512, shake256};

/// Encapsulation key (public) length.
pub const EK_LEN: usize = kpke::EK_LEN;
/// Decapsulation key (secret) length: `dk_PKE ‖ ek ‖ H(ek) ‖ z`.
pub const DK_LEN: usize = kpke::DK_LEN + kpke::EK_LEN + 32 + 32;
/// Ciphertext length.
pub const CT_LEN: usize = kpke::CT_LEN;
/// Shared-secret length.
pub const SS_LEN: usize = 32;

/// Constant-time byte-slice equality (equal length assumed).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// ML-KEM.KeyGen (Alg 16), randomness-injected with seeds `d` and `z`.
/// Returns `(ek, dk)`.
pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, dk_pke) = kpke::keygen(d);
    let h = sha3_256(&ek);
    // dk layout: dk_pke ‖ ek ‖ H(ek) ‖ z. dk_pke is already a Vec of
    // length kpke::DK_LEN; reserving the exact tail size avoids the
    // double-doubling realloc Vec::extend_from_slice would otherwise
    // trigger when growing from 1152 → 2400 bytes.
    let mut dk = dk_pke;
    dk.reserve_exact(DK_LEN - dk.len());
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h);
    dk.extend_from_slice(z);
    debug_assert_eq!(dk.len(), DK_LEN);
    (ek, dk)
}

/// ML-KEM.Encaps (Alg 17), randomness-injected with message `m`. Returns the
/// shared secret and the ciphertext.
pub fn encaps(ek: &[u8], m: &[u8; 32]) -> ([u8; SS_LEN], Vec<u8>) {
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(m);
    g_in[32..].copy_from_slice(&sha3_256(ek));
    let g = sha3_512(&g_in);
    let key: [u8; 32] = g[..32].try_into().unwrap();
    let coins: [u8; 32] = g[32..].try_into().unwrap();
    let ct = kpke::encrypt(ek, m, &coins);
    (key, ct)
}

/// ML-KEM.Decaps (Alg 18): recover the shared secret, with constant-time
/// implicit rejection on a ciphertext that fails re-encryption.
pub fn decaps(dk: &[u8], ct: &[u8]) -> [u8; SS_LEN] {
    let dk_pke = &dk[..kpke::DK_LEN];
    let ek = &dk[kpke::DK_LEN..kpke::DK_LEN + kpke::EK_LEN];
    let h = &dk[kpke::DK_LEN + kpke::EK_LEN..kpke::DK_LEN + kpke::EK_LEN + 32];
    let z = &dk[kpke::DK_LEN + kpke::EK_LEN + 32..];

    let m = kpke::decrypt(dk_pke, ct);

    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m);
    g_in[32..].copy_from_slice(h);
    let g = sha3_512(&g_in);
    let mut key: [u8; 32] = g[..32].try_into().unwrap();
    let coins: [u8; 32] = g[32..].try_into().unwrap();

    // implicit-rejection key J(z ‖ c)
    let mut j_in = Vec::with_capacity(32 + ct.len());
    j_in.extend_from_slice(z);
    j_in.extend_from_slice(ct);
    let mut k_bar = [0u8; 32];
    shake256(&j_in, &mut k_bar);

    // re-encrypt and select in constant time. Convert the equality bool to
    // a byte mask via `wrapping_sub` rather than an `if`-expression — the
    // optimiser is free to lower `if ok { 0 } else { 0xff }` to a branch on
    // some targets, which would leak the FO check outcome via timing. The
    // wrap-arithmetic form compiles to an unconditional cmp+sete+sub on
    // every backend we target.
    let ct2 = kpke::encrypt(ek, &m, &coins);
    let mask = (ct_eq(ct, &ct2) as u8).wrapping_sub(1); // ok → 0; not-ok → 0xff
    for i in 0..32 {
        key[i] = (key[i] & !mask) | (k_bar[i] & mask);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "informational keygen profiling; opt in with `--ignored --nocapture --release`"]
    fn keygen_breakdown_microbench() {
        use super::kpke;
        use super::poly::{
            K, PolyVec, add_in_place, dot_into, gen_matrix, polyvec_ntt_in_place, reduce_in_place,
            to_mont_in_place,
        };
        use super::sample::sample_cbd_eta2;
        use crate::sha3::sha3_512;
        use std::time::Instant;

        let d = [0x11u8; 32];

        // Prepare inputs that mirror kpke::keygen flow
        let mut g_in = [0u8; 33];
        g_in[..32].copy_from_slice(&d);
        g_in[32] = K as u8;
        let g = sha3_512(&g_in);
        let rho: [u8; 32] = g[..32].try_into().unwrap();
        let sigma: [u8; 32] = g[32..].try_into().unwrap();

        // warm
        for _ in 0..50 {
            let _ = super::keygen(&d, &[0; 32]);
        }

        let iters = 2_000u32;

        let mut t_sha3 = 0u128;
        let mut t_matrix = 0u128;
        let mut t_cbd = 0u128;
        let mut t_ntt = 0u128;
        let mut t_dot = 0u128;
        let mut t_to_mont = 0u128;
        let mut t_kpke = 0u128;
        let mut t_mlkem = 0u128;
        let mut t_dk_concat = 0u128;

        for _ in 0..iters {
            let s = Instant::now();
            let _g = std::hint::black_box(sha3_512(std::hint::black_box(&g_in)));
            t_sha3 += s.elapsed().as_nanos();

            let s = Instant::now();
            let a = std::hint::black_box(gen_matrix(&rho, false));
            t_matrix += s.elapsed().as_nanos();

            let s = Instant::now();
            let mut sv: PolyVec = [[0i16; 256]; K];
            let mut ev: PolyVec = [[0i16; 256]; K];
            for i in 0..K {
                sv[i] = sample_cbd_eta2(&sigma, i as u8);
                ev[i] = sample_cbd_eta2(&sigma, (K + i) as u8);
            }
            t_cbd += s.elapsed().as_nanos();

            let s = Instant::now();
            polyvec_ntt_in_place(&mut sv);
            polyvec_ntt_in_place(&mut ev);
            t_ntt += s.elapsed().as_nanos();

            let s = Instant::now();
            let mut t: PolyVec = [[0i16; 256]; K];
            for i in 0..K {
                dot_into(&a[i], &sv, &mut t[i]);
            }
            t_dot += s.elapsed().as_nanos();

            let s = Instant::now();
            for i in 0..K {
                to_mont_in_place(&mut t[i]);
                add_in_place(&mut t[i], &ev[i]);
                reduce_in_place(&mut t[i]);
            }
            t_to_mont += s.elapsed().as_nanos();

            std::hint::black_box(&t);

            let s = Instant::now();
            let _kp = std::hint::black_box(kpke::keygen(&d));
            t_kpke += s.elapsed().as_nanos();

            let s = Instant::now();
            let _full = std::hint::black_box(super::keygen(&d, &[0; 32]));
            t_mlkem += s.elapsed().as_nanos();

            // Just the dk concat at the end of mlkem::keygen
            let (ek, dk_pke) = kpke::keygen(&d);
            let h = sha3_256(&ek);
            let s = Instant::now();
            let mut dk = dk_pke;
            dk.reserve_exact(super::DK_LEN - dk.len());
            dk.extend_from_slice(&ek);
            dk.extend_from_slice(&h);
            dk.extend_from_slice(&[0u8; 32]);
            t_dk_concat += s.elapsed().as_nanos();
            std::hint::black_box(dk);
        }

        let n = u128::from(iters);
        eprintln!("\nML-KEM keygen breakdown ({iters} iters, ns/op):");
        eprintln!("  sha3_512(d||K)            : {} ns", t_sha3 / n);
        eprintln!("  gen_matrix(rho)           : {} ns", t_matrix / n);
        eprintln!("  6 × sample_cbd_eta2       : {} ns", t_cbd / n);
        eprintln!("  polyvec_ntt_in_place × 2  : {} ns", t_ntt / n);
        eprintln!("  dot_into × K              : {} ns", t_dot / n);
        eprintln!("  to_mont+add+reduce × K    : {} ns", t_to_mont / n);
        eprintln!("  --");
        eprintln!("  kpke::keygen TOTAL        : {} ns", t_kpke / n);
        eprintln!("  mlkem::keygen TOTAL       : {} ns", t_mlkem / n);
        eprintln!("  dk concat overhead        : {} ns", t_dk_concat / n);

        // Equivalent encaps + decaps profile to see whether those also
        // benefit from any narrowly-targeted optimization.
        let (ek, dk) = super::keygen(&d, &[0; 32]);
        let m = [0x33u8; 32];

        for _ in 0..50 {
            let _ = super::encaps(&ek, &m);
        }
        let s = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(super::encaps(
                std::hint::black_box(&ek),
                std::hint::black_box(&m),
            ));
        }
        let t_encaps = s.elapsed().as_nanos();

        let (_ss, ct) = super::encaps(&ek, &m);
        for _ in 0..50 {
            let _ = super::decaps(&dk, &ct);
        }
        let s = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(super::decaps(
                std::hint::black_box(&dk),
                std::hint::black_box(&ct),
            ));
        }
        let t_decaps = s.elapsed().as_nanos();

        eprintln!("  mlkem::encaps TOTAL       : {} ns", t_encaps / n);
        eprintln!("  mlkem::decaps TOTAL       : {} ns", t_decaps / n);
    }

    #[test]
    fn sizes_are_mlkem768() {
        assert_eq!(EK_LEN, 1184);
        assert_eq!(DK_LEN, 2400);
        assert_eq!(CT_LEN, 1088);
    }

    #[test]
    fn encaps_decaps_roundtrip() {
        for seed in 0..8u8 {
            let d = [seed; 32];
            let z = [seed ^ 0x5a; 32];
            let m = [seed.wrapping_add(7); 32];
            let (ek, dk) = keygen(&d, &z);
            assert_eq!(ek.len(), EK_LEN);
            assert_eq!(dk.len(), DK_LEN);
            let (k_enc, ct) = encaps(&ek, &m);
            assert_eq!(ct.len(), CT_LEN);
            let k_dec = decaps(&dk, &ct);
            assert_eq!(k_enc, k_dec, "shared secret mismatch (seed {seed})");
        }
    }

    #[test]
    fn tampered_ciphertext_implicitly_rejected() {
        let (ek, dk) = keygen(&[1; 32], &[2; 32]);
        let (k_enc, ct) = encaps(&ek, &[3; 32]);
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        let k_bad = decaps(&dk, &bad);
        // implicit rejection yields a different (pseudo-random) shared secret
        assert_ne!(k_enc, k_bad);
        // and it is deterministic for a given (dk, c)
        assert_eq!(k_bad, decaps(&dk, &bad));
    }

    #[test]
    fn wrong_dk_gives_different_secret() {
        let (ek, _dk) = keygen(&[1; 32], &[2; 32]);
        let (_k, ct) = encaps(&ek, &[3; 32]);
        let (_ek2, dk2) = keygen(&[9; 32], &[8; 32]);
        // decapsulating under an unrelated key must not recover the secret
        let (k_enc, ct2) = encaps(&ek, &[3; 32]);
        assert_eq!(ct, ct2); // encaps is deterministic in m
        assert_ne!(decaps(&dk2, &ct), k_enc);
    }
}
