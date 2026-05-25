//! ML-KEM-768 validated against official NIST FIPS 203 ACVP known-answer
//! vectors. This is the authoritative interoperability check: it proves our
//! keyGen / encaps / decaps agree with NIST's reference, not just with
//! themselves. Vectors are a subset of the NIST ACVP-Server JSON, flattened
//! offline into a simple line format so the test stays zero-dependency (no
//! JSON parser in the build).

use gnet_crypto::mlkem;

const VECTORS: &str = include_str!("mlkem_acvp_768.txt");

/// Decode an ASCII hex string into bytes (lower- or upper-case).
fn hex(s: &str) -> Vec<u8> {
    fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit {c:?}"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    s.chunks(2).map(|p| (nib(p[0]) << 4) | nib(p[1])).collect()
}

fn arr32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("expected 32 bytes")
}

/// Iterate the fixture lines for one operation, yielding the whitespace fields.
fn cases(op: &str) -> impl Iterator<Item = Vec<&'static str>> {
    VECTORS.lines().filter_map(move |line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        (f[0] == op).then(|| f[1..].to_vec())
    })
}

#[test]
fn keygen_matches_acvp() {
    let mut n = 0;
    for f in cases("keygen") {
        let (d, z, ek_exp, dk_exp) = (hex(f[0]), hex(f[1]), hex(f[2]), hex(f[3]));
        let (ek, dk) = mlkem::keygen(&arr32(&d), &arr32(&z));
        assert_eq!(ek, ek_exp, "keygen ek mismatch (case {n})");
        assert_eq!(dk, dk_exp, "keygen dk mismatch (case {n})");
        n += 1;
    }
    assert!(n >= 25, "expected the full ACVP keygen subset, got {n}");
}

#[test]
fn encaps_matches_acvp() {
    let mut n = 0;
    for f in cases("encaps") {
        let (ek, m, c_exp, k_exp) = (hex(f[0]), hex(f[1]), hex(f[2]), hex(f[3]));
        let (ss, ct) = mlkem::encaps(&ek, &arr32(&m));
        assert_eq!(ct, c_exp, "encaps ciphertext mismatch (case {n})");
        assert_eq!(
            ss.to_vec(),
            k_exp,
            "encaps shared secret mismatch (case {n})"
        );
        n += 1;
    }
    assert!(n >= 25, "expected the full ACVP encaps subset, got {n}");
}

#[test]
fn decaps_matches_acvp() {
    let mut n = 0;
    for f in cases("decaps") {
        let (dk, c, k_exp) = (hex(f[0]), hex(f[1]), hex(f[2]));
        let ss = mlkem::decaps(&dk, &c);
        // covers valid ciphertexts and implicit-reject cases — the expected k
        // is whatever FIPS 203 decaps returns either way.
        assert_eq!(
            ss.to_vec(),
            k_exp,
            "decaps shared secret mismatch (case {n})"
        );
        n += 1;
    }
    assert!(n >= 10, "expected the full ACVP decaps subset, got {n}");
}
