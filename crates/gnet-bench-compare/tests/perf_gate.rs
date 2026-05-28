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

use rand_core::RngCore;
use std::hint::black_box;
use std::time::Instant;

const ITERS_X25519: u32 = 1_000;
const ITERS_AEAD: u32 = 1_000;
const ITERS_MLKEM: u32 = 100;
const ITERS_NOISE: u32 = 100;
const ITERS_HEX: u32 = 200_000;

/// Number of independent timing samples each category takes; the test
/// asserts on the **fastest** (minimum) of these samples — "best-of-N",
/// the standard microbenchmark protocol for noisy / frequency-scaling
/// hardware. Shared lx64 + GH Actions VMs run the `powersave` CPU
/// governor by default; under powersave the same code can take 1.5×
/// longer for many seconds at a stretch (turbo deactivates), then snap
/// back. Median-of-N is stable when all N samples land in the same
/// state — which is precisely what bimodal stretching does to a small
/// window. Min-of-N picks the run where the CPU was unblocked, which is
/// the code's actual cost when not externally throttled. Both gnet and
/// competitor pick their own min independently on the same hardware,
/// so the ratio still cancels architecture noise but no longer carries
/// state-dependent stretching.
const BEST_OF: usize = 20;

/// Time a closure over `iters` iterations after `iters/4` warm-up calls.
/// Returns the average ns per iteration of a single sample.
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

/// Take `BEST_OF` independent timing samples and return the **fastest**.
/// "Fastest" is what the code achieves when the CPU is at its peak
/// frequency without preemption — i.e. the per-iter cost the
/// implementation actually pays. See [`BEST_OF`] for the rationale.
fn measure_best(iters: u32, mut f: impl FnMut()) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..BEST_OF {
        let sample = measure(iters, &mut f);
        if sample < best {
            best = sample;
        }
    }
    best
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
// Baseline 2026-05-27: gnet 1.08-1.19× FASTER than dalek. Median ratio
// stable at ~0.93. Cap ratchetted from 1.10 → 1.05 to lock in the win.

#[test]
fn x25519_must_not_lose_to_dalek() {
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let sk = gnet_rand::random_32();
    let pk = gnet_crypto::x25519::x25519(&sk, &basepoint);

    let gnet_ns = measure_best(ITERS_X25519, || {
        let ss = gnet_crypto::x25519::x25519(black_box(&sk), black_box(&pk));
        black_box(ss);
    });

    use x25519_dalek::{PublicKey, StaticSecret};
    let dalek_sk = StaticSecret::from(sk);
    let dalek_pk = PublicKey::from(pk);
    let comp_ns = measure_best(ITERS_X25519, || {
        let ss = black_box(&dalek_sk).diffie_hellman(black_box(&dalek_pk));
        black_box(ss);
    });

    assert_ratio("X25519 ECDH", gnet_ns, comp_ns, 1.05);
}

// ───── AEAD ChaCha20-Poly1305 ─────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.5-1.7× FASTER. Median seal ~0.66, open
// ~0.65. Cap ratchetted from 1.10 → 1.05 to lock in the win.

#[test]
fn aead_seal_must_not_lose_to_rustcrypto() {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
    let key = gnet_rand::random_32();
    let nonce = [0u8; 12];
    let aad = [0u8; 16];
    let payload = vec![0xABu8; 1400];

    let mut buf = vec![0u8; 1400];
    let gnet_ns = measure_best(ITERS_AEAD, || {
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
    let comp_ns = measure_best(ITERS_AEAD, || {
        comp_buf.clear();
        comp_buf.extend_from_slice(&payload);
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut comp_buf)
            .expect("encrypt");
        black_box(&comp_buf);
    });

    assert_ratio("AEAD seal 1400B", gnet_ns, comp_ns, 1.05);
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
    let gnet_ns = measure_best(ITERS_AEAD, || {
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
    let comp_ns = measure_best(ITERS_AEAD, || {
        comp_open.clear();
        comp_open.extend_from_slice(&comp_sealed);
        cipher
            .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut comp_open)
            .expect("decrypt");
        black_box(&comp_open);
    });

    assert_ratio("AEAD open 1400B", gnet_ns, comp_ns, 1.05);
}

// ───── ML-KEM-768 ─────────────────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.2-1.9× SLOWER than RustCrypto. The TASKS.md
// backlog drives this toward < 1.0 via NTT precomp + SIMD layout. Until
// then, the hardgate captures the current ratio + 1.3 noise margin and
// is ratcheted down as each polish task lands.

#[test]
fn mlkem_keygen_hardgate() {
    // Pre-fill a pool of (d, z) seed pairs outside the timed loop so that
    // each iteration just rotates an index — no in-loop `getrandom(2)`.
    // macOS `getrandom` is ~22 µs/call and would otherwise dominate the
    // measurement (a single keygen is ~20 µs in pure crypto).
    let mut rng = TestRng::new();
    const POOL: usize = 64;
    let mut seeds = [[[0u8; 32]; 2]; POOL];
    for slot in &mut seeds {
        rng.fill_bytes(&mut slot[0]);
        rng.fill_bytes(&mut slot[1]);
    }
    let mut idx = 0usize;
    let gnet_ns = measure_best(ITERS_MLKEM, || {
        let (d, z) = (&seeds[idx % POOL][0], &seeds[idx % POOL][1]);
        idx += 1;
        black_box(gnet_crypto::mlkem::keygen(black_box(d), black_box(z)));
    });

    use ml_kem::KemCore;
    use ml_kem::MlKem768;
    let mut rng = TestRng::new();
    let comp_ns = measure_best(ITERS_MLKEM, || {
        let (dk, ek) = MlKem768::generate(black_box(&mut rng));
        black_box((dk, ek));
    });

    // 2026-05-27 history:
    //   Baseline 1.88 (Apple) / 1.67 (Linux) → T-2.4 in-place poly ops +
    //   sha3 lane-aligned squeeze → T-2.5 Keccak-x4 NEON + NTT/invNTT/
    //   ntt_mul NEON 8-way → byte_encode/decode fast paths for d ∈
    //   {12, 10, 4, 1} (the old LSB-by-LSB loop was 5–8× slower than
    //   needed) → 0.55 (Apple median of 5) / 0.69 (Linux). The bench
    //   harness was also rewritten in the same commit to use a
    //   deterministic non-syscall TestRng on both sides — the prior
    //   harness mixed `gnet_rand::fill` (≈ 22 µs / call on macOS) into
    //   the gnet loop while the competitor's internal RNG made fewer
    //   syscalls, masking the true algorithmic ratio.
    //
    // 2026-05-28: x86_64 cap loosened 0.85 → 1.20 to absorb the observed
    // bimodal CPU-governor behaviour on lx64 (powersave default puts the
    // CPU in a slow cluster for tens of seconds at a time; ~30% of runs
    // measure gnet at 1.13× even though the typical best-of-10 ratio is
    // 0.68×). Apple cap stays tight — Apple Silicon doesn't exhibit the
    // same bimodal stretching. AVX2 NTT work (v0.8) will further tighten
    // the typical x86_64 ratio; only after that does this cap re-ratchet.
    //
    // 2026-05-28 (v0.8 S2): x86_64 cap ratchetted 1.20 → 0.90 after AVX2
    // Keccak-x4 landed for ML-KEM matrix gen. Typical ratio is 0.50-0.51
    // (down from 0.68 pre-AVX2 — matrix gen drops from 9 serial SHAKE128
    // streams to 2 × 4-way + 1 scalar, ~26% relative improvement on
    // keygen specifically). The slow-cluster envelope shrunk from
    // 1.08-1.13 to 0.79-0.80 because the absolute time is shorter and
    // the same scheduling spike weighs less.
    let cap = if cfg!(target_arch = "aarch64") { 0.70 } else { 0.90 };
    assert_ratio("ML-KEM keygen", gnet_ns, comp_ns, cap);
}

#[test]
fn mlkem_encaps_hardgate() {
    let mut bootstrap = TestRng::new();
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    bootstrap.fill_bytes(&mut d);
    bootstrap.fill_bytes(&mut z);
    let (ek, _dk) = gnet_crypto::mlkem::keygen(&d, &z);

    // Pool of randomness-injected `m` values, pre-filled outside the
    // timed loop — same reasoning as mlkem_keygen_hardgate.
    const POOL: usize = 64;
    let mut ms = [[0u8; 32]; POOL];
    for m in &mut ms {
        bootstrap.fill_bytes(m);
    }
    let mut idx = 0usize;
    let gnet_ns = measure_best(ITERS_MLKEM, || {
        let m = &ms[idx % POOL];
        idx += 1;
        black_box(gnet_crypto::mlkem::encaps(black_box(&ek), black_box(m)));
    });

    use ml_kem::KemCore;
    use ml_kem::MlKem768;
    use ml_kem::kem::Encapsulate;
    let mut rng = TestRng::new();
    let (_, comp_ek) = MlKem768::generate(&mut rng);
    let comp_ns = measure_best(ITERS_MLKEM, || {
        let (ct, ss) = black_box(&comp_ek)
            .encapsulate(black_box(&mut rng))
            .expect("encaps");
        black_box((ct, ss));
    });

    // 2026-05-27 history:
    //   Baseline 1.62 (Apple) → T-2.4 → T-2.5 Keccak-x4 + NTT SIMD +
    //   byte_encode/decode fast paths + fair RNG harness → 0.51 (Apple
    //   median of 5) / 0.73 (Linux). Encaps's serialization step
    //   (compress + byte_encode_d10 for u, byte_encode_d4 for v) was
    //   the largest single beneficiary of the fast-path packers.
    //
    // 2026-05-28: x86_64 cap kept at 0.85 — best-of-10 measurements stay
    // stably under 0.74 even in lx64's slow cluster, so the original
    // ratchet survives the noise envelope. See `mlkem_keygen` cap
    // comment for the wider bimodal context.
    //
    // 2026-05-28 (v0.8 S1): x86_64 cap ratchetted 0.85 → 0.78 after AVX2
    // 16-way NTT/invNTT landed. Typical ratio is 0.63-0.66 (~11% relative
    // improvement from the SIMD butterflies covering layers len ∈
    // {128, 64, 32, 16}), but the lx64 slow-cluster CPU-governor state
    // can pull the ratio up to ~0.72 — cap 0.78 leaves a thin envelope
    // for the slow cluster while still gating any real regression.
    //
    // 2026-05-28 (v0.8 S2): x86_64 cap stays 0.90 (briefly 0.78 then
    // loosened) after AVX2 Keccak-x4 landed. Typical ratio dropped
    // further to 0.50-0.51 (matrix gen via 4-way SHAKE128 instead of
    // serial), but slow-cluster bimodality reaches 0.84-0.85 because
    // the absolute time is shorter and CPU scheduling spikes weigh more
    // relatively. Cap 0.90 catches any real regression while passing the
    // slow-cluster envelope.
    let cap = if cfg!(target_arch = "aarch64") { 0.65 } else { 0.90 };
    assert_ratio("ML-KEM encaps", gnet_ns, comp_ns, cap);
}

#[test]
fn mlkem_decaps_hardgate() {
    let mut bootstrap = TestRng::new();
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    bootstrap.fill_bytes(&mut d);
    bootstrap.fill_bytes(&mut z);
    let (ek, dk) = gnet_crypto::mlkem::keygen(&d, &z);
    let mut m = [0u8; 32];
    bootstrap.fill_bytes(&mut m);
    let (_ss, ct) = gnet_crypto::mlkem::encaps(&ek, &m);
    let gnet_ns = measure_best(ITERS_MLKEM, || {
        let ss = gnet_crypto::mlkem::decaps(black_box(&dk), black_box(&ct));
        black_box(ss);
    });

    use ml_kem::KemCore;
    use ml_kem::MlKem768;
    use ml_kem::kem::{Decapsulate, Encapsulate};
    let mut rng = TestRng::new();
    let (comp_dk, comp_ek) = MlKem768::generate(&mut rng);
    let (comp_ct, _) = comp_ek.encapsulate(&mut rng).expect("encaps");
    let comp_ns = measure_best(ITERS_MLKEM, || {
        let ss = black_box(&comp_dk)
            .decapsulate(black_box(&comp_ct))
            .expect("decaps");
        black_box(ss);
    });

    // 2026-05-27 history:
    //   Baseline 1.17 (Apple) → T-2.4 → 1.03 → T-2.5 Keccak-x4 + NTT
    //   SIMD → 0.88 → byte_encode/decode fast paths + fair RNG harness
    //   → 0.45 (Apple median of 5) / 0.66 (Linux). decaps was already
    //   winning before this commit; the serialize fast paths + harness
    //   fix took it from "parity" to "gnet 2× faster".
    //
    // 2026-05-28: x86_64 cap loosened 0.80 → 1.15 to absorb occasional
    // spikes (one decaps in ~5 lx64 runs measured 1.08×, the rest stable
    // at 0.66-0.67). Same bimodal-CPU rationale as `mlkem_keygen`.
    //
    // 2026-05-28 (v0.8 S1): x86_64 cap ratchetted 1.15 → 1.05 after AVX2
    // 16-way NTT/invNTT landed. Typical ratio is 0.57-0.58 (~13% relative
    // improvement — decaps does two NTT roundtrips for the re-encrypt
    // step), but the lx64 slow-cluster CPU-governor state stretches
    // decaps to ~56 µs (vs ~32 µs fast) for several seconds at a stretch
    // and reaches ~1.0 occasionally even under best-of-20. Cap 1.05
    // catches any real regression (gnet ≥ 5% stably slower than
    // competitor) while passing the slow-cluster envelope. The AVX2
    // ratchet lives in the comment + commit history, not the numeric
    // cap, until the lx64 governor / GH runner CPU stability improves.
    //
    // 2026-05-28 (v0.8 S2): x86_64 cap ratchetted 1.05 → 0.85 after AVX2
    // Keccak-x4 reduced the absolute decaps time enough that even the
    // slow cluster lands at 0.77-0.79 (vs typical 0.46-0.47). Cap 0.85
    // gates real regressions (≥ 8% slower than competitor) while
    // absorbing the bimodal envelope.
    let cap = if cfg!(target_arch = "aarch64") { 0.60 } else { 0.85 };
    assert_ratio("ML-KEM decaps", gnet_ns, comp_ns, cap);
}

// ───── Noise_IK classic handshake ─────────────────────────────────────
// Baseline 2026-05-27: gnet 1.22× (Apple) / 1.14× (Linux) slower than snow.
// After Phase 1 allocation polish and T-1.4 (Edwards basepoint comb),
// gnet is now ~0.95× snow on Apple. Cap ratchetted to 1.05.

#[test]
fn noise_ik_classic_hardgate() {
    use gnet_noise::handshake::{Initiator, Responder};
    use snow::{Builder, params::NoiseParams};

    let ini_sk = gnet_rand::random_32();
    let resp_sk = gnet_rand::random_32();
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let resp_pk = gnet_crypto::x25519::x25519(&resp_sk, &basepoint);

    let gnet_ns = measure_best(ITERS_NOISE, || {
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
    let comp_ns = measure_best(ITERS_NOISE, || {
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

    // Baseline 2026-05-27 was 1.22 (Apple) / 1.14 (Linux). After Phase 1
    // (allocation-free Hasher + HKDF / single-Vec output), T-1.4 (X25519
    // Edwards-basepoint comb), the width-5 comb refinement, and the
    // x25519_base_pair batch-inversion (one finvert shared across the
    // static + ephemeral derivations in `Initiator::new` /
    // `Responder::new`), gnet's median lands at ~0.91 on Apple / ~0.87
    // on lx64. Cap 1.00 tightens the lock-the-win line — we should never
    // again be slower than snow on either arch.
    assert_ratio("Noise_IK classic handshake", gnet_ns, comp_ns, 1.00);
}

// ───── Hex codec ──────────────────────────────────────────────────────
// Baseline 2026-05-27: gnet 1.08-2.89× FASTER. Median encode ~0.52,
// decode ~0.78. Cap ratchetted from 1.20 → 1.05 to lock in the win.

#[test]
fn hex_encode_32_must_not_lose() {
    let key = [0xABu8; 32];
    let gnet_ns = measure_best(ITERS_HEX, || {
        let s = gnet_hex::encode(black_box(&key));
        black_box(s);
    });
    let comp_ns = measure_best(ITERS_HEX, || {
        let s = hex::encode(black_box(&key));
        black_box(s);
    });
    assert_ratio("Hex encode 32B", gnet_ns, comp_ns, 1.05);
}

#[test]
fn hex_decode_32_must_not_lose() {
    let key = [0xABu8; 32];
    let hex32 = gnet_hex::encode(&key);
    let gnet_ns = measure_best(ITERS_HEX, || {
        let b = gnet_hex::decode_32(black_box(&hex32));
        black_box(b);
    });
    let comp_ns = measure_best(ITERS_HEX, || {
        let mut out = [0u8; 32];
        hex::decode_to_slice(black_box(&hex32), black_box(&mut out)).expect("decode");
        black_box(out);
    });
    assert_ratio("Hex decode 32B", gnet_ns, comp_ns, 1.05);
}

// ───── rand_core 0.6 shim for ml_kem ──────────────────────────────────
//
// A deterministic, syscall-free RNG so that ML-KEM benches measure
// algorithmic cost rather than `getrandom(2)` overhead. macOS getrandom
// is ~22 µs / call — large enough to swamp the actual keygen / encaps
// work and produce misleading ratios (a one-call-vs-two-call asymmetry
// between the bench loop and the competitor's internal RNG usage would
// otherwise dominate the comparison).
//
// Seed bytes come from a single up-front `gnet_rand::fill` outside any
// timed measurement; the in-loop `fill_bytes` is then just a counter-
// driven Linear Congruential pull, ≪ 100 ns per call.

struct TestRng {
    state: u64,
}

impl TestRng {
    fn new() -> Self {
        // One-off seed — outside any `measure(...)` loop.
        let mut s = [0u8; 8];
        gnet_rand::fill(&mut s);
        TestRng {
            state: u64::from_le_bytes(s).max(1),
        }
    }

    #[inline(always)]
    fn next_byte(&mut self) -> u8 {
        // splitmix64 step — uniform, fast, syscall-free.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) as u8
    }
}

impl rand_core::CryptoRng for TestRng {}
impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_byte();
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
