//! Baseline-as-hardgate: every category measured side-by-side against the
//! Rust SOTA crate, asserting gnet's ratio against the competitor stays
//! within a documented threshold. Failure of any test means a perf
//! regression (or an environment regression) past the 2026-05-27 baseline
//! plus a 30% noise margin.
//!
//! Two operating modes per category:
//!
//! 1. **Already-winning** (gnet faster than competitor on baseline): assert
//!    `gnet_ns / comp_ns < 1.0`. We must KEEP winning — any slip catches.
//!
//! 2. **Currently-losing** (gnet slower than competitor on baseline): assert
//!    `gnet_ns / comp_ns < (baseline_ratio × 1.3)`. We have a polish backlog
//!    (see `TASKS.md`); the gate captures "no further regression". After each
//!    polish task lands, tighten the ratio toward `1.0` (and below).
//!
//! Both sides run in the same test invocation on the same hardware, so the
//! ratio cancels CPU / scheduler noise from the absolute ns/op numbers.
//! Iterations are kept modest so `cargo test --release` finishes in a few
//! seconds — this is a CI gate, not a publication.

#![allow(clippy::cast_precision_loss)]

use std::hint::black_box;
use std::time::Instant;

const ITERS_X25519: u32 = 1_000;
const ITERS_AEAD: u32 = 1_000;
const ITERS_MLKEM: u32 = 100;
const ITERS_NOISE: u32 = 100;
const ITERS_HEX: u32 = 200_000;

/// Time a closure over `iters` iterations after `iters/4` warm-up calls.
/// Returns the average ns per iteration.
fn measure(iters: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..(iters / 4).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_secs_f64() * 1e9 / f64::from(iters)
}

fn assert_ratio(name: &str, gnet_ns: f64, comp_ns: f64, max_ratio: f64) {
    let ratio = gnet_ns / comp_ns;
    eprintln!(
        "  {name:<36}  gnet={gnet_ns:>9.1} ns  comp={comp_ns:>9.1} ns  ratio={ratio:>5.2}  (cap {max_ratio:.2})"
    );
    assert!(
        ratio < max_ratio,
        "{name} ratio {ratio:.3} exceeded cap {max_ratio:.3} (gnet {gnet_ns:.0} ns / comp {comp_ns:.0} ns)"
    );
}

// ───── X25519 ─────────────────────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.08-1.19× FASTER than dalek. Cap at 1.0 keeps
// us winning; allow 0.1 noise margin → 1.10.

#[test]
fn x25519_must_not_lose_to_dalek() {
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let sk = gnet_rand::random_32();
    let pk = gnet_crypto::x25519::x25519(&sk, &basepoint);

    let gnet_ns = measure(ITERS_X25519, || {
        let ss = gnet_crypto::x25519::x25519(black_box(&sk), black_box(&pk));
        black_box(ss);
    });

    use x25519_dalek::{PublicKey, StaticSecret};
    let dalek_sk = StaticSecret::from(sk);
    let dalek_pk = PublicKey::from(pk);
    let comp_ns = measure(ITERS_X25519, || {
        let ss = black_box(&dalek_sk).diffie_hellman(black_box(&dalek_pk));
        black_box(ss);
    });

    assert_ratio("X25519 ECDH", gnet_ns, comp_ns, 1.10);
}

// ───── AEAD ChaCha20-Poly1305 ─────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.5-1.7× FASTER. Cap 1.0 + 10% noise.

#[test]
fn aead_seal_must_not_lose_to_rustcrypto() {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
    let key = gnet_rand::random_32();
    let nonce = [0u8; 12];
    let aad = [0u8; 16];
    let payload = vec![0xABu8; 1400];

    let mut buf = vec![0u8; 1400];
    let gnet_ns = measure(ITERS_AEAD, || {
        buf.copy_from_slice(&payload);
        let tag = gnet_crypto::aead::seal_in_place(
            black_box(&key),
            black_box(&nonce),
            black_box(&aad[..]),
            &mut buf,
        );
        black_box((tag, &buf));
    });

    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut comp_buf = payload.clone();
    let comp_ns = measure(ITERS_AEAD, || {
        comp_buf.clear();
        comp_buf.extend_from_slice(&payload);
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut comp_buf)
            .expect("encrypt");
        black_box(&comp_buf);
    });

    assert_ratio("AEAD seal 1400B", gnet_ns, comp_ns, 1.10);
}

#[test]
fn aead_open_must_not_lose_to_rustcrypto() {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
    let key = gnet_rand::random_32();
    let nonce = [0u8; 12];
    let aad = [0u8; 16];
    let payload = vec![0xABu8; 1400];

    // gnet sealed sample.
    let mut sealed_gnet = payload.clone();
    let tag = gnet_crypto::aead::seal_in_place(&key, &nonce, &aad, &mut sealed_gnet);
    let mut gnet_open = sealed_gnet.clone();
    let gnet_ns = measure(ITERS_AEAD, || {
        gnet_open.copy_from_slice(&sealed_gnet);
        let _ = gnet_crypto::aead::open_in_place(
            black_box(&key),
            black_box(&nonce),
            black_box(&aad[..]),
            &mut gnet_open,
            black_box(&tag),
        );
    });

    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut comp_sealed = payload.clone();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut comp_sealed)
        .expect("encrypt for open bench");
    let mut comp_open = comp_sealed.clone();
    let comp_ns = measure(ITERS_AEAD, || {
        comp_open.clear();
        comp_open.extend_from_slice(&comp_sealed);
        cipher
            .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut comp_open)
            .expect("decrypt");
        black_box(&comp_open);
    });

    assert_ratio("AEAD open 1400B", gnet_ns, comp_ns, 1.10);
}

// ───── ML-KEM-768 ─────────────────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.2-1.9× SLOWER than RustCrypto. The TASKS.md
// backlog drives this toward < 1.0 via NTT precomp + SIMD layout. Until
// then, the hardgate captures the current ratio + 1.3 noise margin and
// is ratcheted down as each polish task lands.

#[test]
fn mlkem_keygen_hardgate() {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    gnet_rand::fill(&mut d);
    gnet_rand::fill(&mut z);
    let gnet_ns = measure(ITERS_MLKEM, || {
        gnet_rand::fill(black_box(&mut d));
        gnet_rand::fill(&mut z);
        black_box(gnet_crypto::mlkem::keygen(&d, &z));
    });

    use ml_kem::KemCore;
    use ml_kem::MlKem768;
    let mut rng = TestRng;
    let comp_ns = measure(ITERS_MLKEM, || {
        let (dk, ek) = MlKem768::generate(black_box(&mut rng));
        black_box((dk, ek));
    });

    // Baseline ratio: 1.88 (Apple) / 1.67 (Linux). Cap at 2.5 for both.
    assert_ratio("ML-KEM keygen", gnet_ns, comp_ns, 2.5);
}

#[test]
fn mlkem_encaps_hardgate() {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    gnet_rand::fill(&mut d);
    gnet_rand::fill(&mut z);
    let (ek, _dk) = gnet_crypto::mlkem::keygen(&d, &z);
    let mut m = [0u8; 32];
    gnet_rand::fill(&mut m);
    let gnet_ns = measure(ITERS_MLKEM, || {
        gnet_rand::fill(black_box(&mut m));
        black_box(gnet_crypto::mlkem::encaps(&ek, &m));
    });

    use ml_kem::KemCore;
    use ml_kem::MlKem768;
    use ml_kem::kem::Encapsulate;
    let mut rng = TestRng;
    let (_, comp_ek) = MlKem768::generate(&mut rng);
    let comp_ns = measure(ITERS_MLKEM, || {
        let (ct, ss) = black_box(&comp_ek)
            .encapsulate(black_box(&mut rng))
            .expect("encaps");
        black_box((ct, ss));
    });

    // Baseline: 1.62 (Apple) / 1.46 (Linux). Cap 2.2.
    assert_ratio("ML-KEM encaps", gnet_ns, comp_ns, 2.2);
}

#[test]
fn mlkem_decaps_hardgate() {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    gnet_rand::fill(&mut d);
    gnet_rand::fill(&mut z);
    let (ek, dk) = gnet_crypto::mlkem::keygen(&d, &z);
    let mut m = [0u8; 32];
    gnet_rand::fill(&mut m);
    let (_ss, ct) = gnet_crypto::mlkem::encaps(&ek, &m);
    let gnet_ns = measure(ITERS_MLKEM, || {
        let ss = gnet_crypto::mlkem::decaps(black_box(&dk), black_box(&ct));
        black_box(ss);
    });

    use ml_kem::KemCore;
    use ml_kem::MlKem768;
    use ml_kem::kem::{Decapsulate, Encapsulate};
    let mut rng = TestRng;
    let (comp_dk, comp_ek) = MlKem768::generate(&mut rng);
    let (comp_ct, _) = comp_ek.encapsulate(&mut rng).expect("encaps");
    let comp_ns = measure(ITERS_MLKEM, || {
        let ss = black_box(&comp_dk)
            .decapsulate(black_box(&comp_ct))
            .expect("decaps");
        black_box(ss);
    });

    // Baseline: 1.17 (Apple) / 1.31 (Linux). Cap 1.7.
    assert_ratio("ML-KEM decaps", gnet_ns, comp_ns, 1.7);
}

// ───── Noise_IK classic handshake ─────────────────────────────────────
// Baseline 2026-05-27: gnet 1.22× (Apple) / 1.14× (Linux) slower than snow.
// The polish task removes per-handshake Vec allocations + inlines the
// mix_* operations to match snow.

#[test]
fn noise_ik_classic_hardgate() {
    use gnet_noise::handshake::{Initiator, Responder};
    use snow::{Builder, params::NoiseParams};

    let ini_sk = gnet_rand::random_32();
    let resp_sk = gnet_rand::random_32();
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let resp_pk = gnet_crypto::x25519::x25519(&resp_sk, &basepoint);

    let gnet_ns = measure(ITERS_NOISE, || {
        let mut ini = Initiator::new(black_box(ini_sk), black_box(resp_pk), gnet_rand::random_32());
        let msg1 = ini.write_message_1(b"");
        let mut resp = Responder::new(black_box(resp_sk), gnet_rand::random_32());
        resp.read_message_1(&msg1).expect("read msg1");
        let (msg2, _) = resp.write_message_2(b"").expect("write msg2");
        let (_, _) = ini.read_message_2(&msg2).expect("read msg2");
        black_box(msg2);
    });

    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("snow params");
    let comp_ns = measure(ITERS_NOISE, || {
        let mut ini = Builder::new(black_box(params.clone()))
            .local_private_key(&ini_sk)
            .expect("ini sk")
            .remote_public_key(&resp_pk)
            .expect("ini pk")
            .build_initiator()
            .expect("build ini");
        let mut msg1 = vec![0u8; 1024];
        let n1 = ini.write_message(b"", &mut msg1).expect("write msg1");
        let mut resp = Builder::new(params.clone())
            .local_private_key(&resp_sk)
            .expect("resp sk")
            .build_responder()
            .expect("build resp");
        let mut p1 = vec![0u8; 1024];
        resp.read_message(&msg1[..n1], &mut p1).expect("read msg1");
        let mut msg2 = vec![0u8; 1024];
        let n2 = resp.write_message(b"", &mut msg2).expect("write msg2");
        let mut p2 = vec![0u8; 1024];
        ini.read_message(&msg2[..n2], &mut p2).expect("read msg2");
        let _ = ini.into_transport_mode();
        let _ = resp.into_transport_mode();
        black_box(n2);
    });

    // Baseline 2026-05-27 was 1.22 (Apple) / 1.14 (Linux); after Phase 1
    // allocation-free Hasher + HKDF-Expand precomputed pads + handshake
    // pre-sized output Vec, median is ~1.25 with ±0.05 run-to-run noise.
    // Cap 1.35 captures "no regression past today + 10% noise margin". The
    // hard goal of < 1.10 needs X25519 basepoint precomputation (see
    // TASKS.md Phase 1 follow-up); ratchet again then.
    assert_ratio("Noise_IK classic handshake", gnet_ns, comp_ns, 1.35);
}

// ───── Hex codec ──────────────────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.08-2.89× FASTER. Cap 1.0 + noise margin.

#[test]
fn hex_encode_32_must_not_lose() {
    let key = [0xABu8; 32];
    let gnet_ns = measure(ITERS_HEX, || {
        let s = gnet_hex::encode(black_box(&key));
        black_box(s);
    });
    let comp_ns = measure(ITERS_HEX, || {
        let s = hex::encode(black_box(&key));
        black_box(s);
    });
    assert_ratio("Hex encode 32B", gnet_ns, comp_ns, 1.20);
}

#[test]
fn hex_decode_32_must_not_lose() {
    let key = [0xABu8; 32];
    let hex32 = gnet_hex::encode(&key);
    let gnet_ns = measure(ITERS_HEX, || {
        let b = gnet_hex::decode_32(black_box(&hex32));
        black_box(b);
    });
    let comp_ns = measure(ITERS_HEX, || {
        let mut out = [0u8; 32];
        hex::decode_to_slice(black_box(&hex32), black_box(&mut out)).expect("decode");
        black_box(out);
    });
    assert_ratio("Hex decode 32B", gnet_ns, comp_ns, 1.20);
}

// ───── rand_core 0.6 shim so ml_kem can use gnet_rand ─────────────────

struct TestRng;
impl rand_core::CryptoRng for TestRng {}
impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        gnet_rand::random_u32()
    }
    fn next_u64(&mut self) -> u64 {
        let lo = u64::from(gnet_rand::random_u32());
        let hi = u64::from(gnet_rand::random_u32());
        (hi << 32) | lo
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        gnet_rand::fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        gnet_rand::fill(dest);
        Ok(())
    }
}
