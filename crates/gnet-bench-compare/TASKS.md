# Perf polish — linear task list

Goal (non-negotiable): on every category in this crate's comparison matrix,
**gnet < competitor**. No exceptions. Today five categories are already
faster; three are slower and one is roughly tied. We close every gap.

Ordering: highest expected ROI first. Each task is self-contained — its
acceptance is a measurable ratio improvement against the hardgate at
`tests/perf_gate.rs`, and the gate's `max_ratio` parameter is tightened by
the same commit.

Reference allowed: study competitor source for **technique** (NTT
precomputation tables, in-place state layout, Montgomery reduction tricks,
etc.). Do **not** copy code — gnet is zero-dep, 100% hand-written, and the
licence story stays clean.

---

## Phase 1 — Noise_IK overhead polish — **DONE (2026-05-27)**

**Current state**: classic Noise_IK handshake is **~0.98× snow on Apple**
(gnet 212 µs, snow 217 µs). Phases 1+2+T-1.4 closed the entire gap and
flipped the category. Hardgate cap ratchetted to **1.05** (matching the
other winning categories).

History:
- 2026-05-27 baseline: ~1.25× snow (T-1.1/T-1.2/T-1.3 done)
- + T-1.4 (Edwards basepoint comb): **0.98× snow** ← win

### T-1.1 Profile gnet-noise classic handshake allocations

- File: `crates/gnet-noise/src/handshake.rs`
- Look at `write_message_1`, `read_message_1`, `write_message_2`,
  `read_message_2`. Count `Vec` allocations and intermediate `String`s.
- Compare with `snow/src/handshakestate.rs` design — snow reuses a
  pre-allocated buffer; we likely build fresh `Vec`s per step.
- Verify: `cargo bench -p gnet-bench-compare --bench noise` shows the
  baseline.

### T-1.2 Reuse buffers across handshake steps

- Refactor `Initiator` / `Responder` to hold a `[u8; 1024]` scratch
  buffer; `write_message_*` returns `&[u8]` borrowed from it instead
  of a fresh `Vec`.
- Update callers (`gnet/src/node/handshake.rs`, tests) — the borrow
  lifetime is the handshake step, easy to thread.
- Acceptance: classic Noise_IK hardgate ratio drops below 1.10.

### T-1.3 Inline mix_hash / mix_key fast paths

- File: `crates/gnet-noise/src/symmetric_state.rs`
- Annotate `mix_hash`, `mix_key`, `encrypt_and_hash` with `#[inline]`
  if not already; check generated asm with `cargo asm` or rustc emit.
- snow inlines via a `SymmetricState` enum dispatch — verify ours
  doesn't pay a vtable cost.
- Acceptance: hardgate ratio drops below 1.0.

### T-1.4 (follow-up) X25519 basepoint precomputation — **DONE**

- Files: `crates/gnet-crypto/src/x25519/{field,scalar,edwards,base_table,base}.rs`
  (split from the single `x25519.rs`).
- `pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32]` shipped via an
  Edwards twisted-curve comb: 4-bit signed-digit recoding × 64
  windows × 8 cached multiples = **60 KiB rodata table** (Fe-form;
  no per-lookup unpack). Compile-time const-fn build, KAT'd against
  RFC 7748 §6.1 + 64 random-scalar differential vs the Montgomery
  ladder.
- All four `public_of` call sites routed (`gnet-noise::handshake`,
  `gnet-noise::hybrid`, plus `gnet::keys` for `generate_static` /
  `public_key`).
- Reference: HWCD-2008 extended-coord formulas + RFC 8032 §5.1
  basepoint + Bernstein donna-c64 schedule. Constants re-derived
  (`d = -121665/121666` const-computed via `finvert`). No code from
  curve25519-dalek copied.
- Result: **6.3 µs/op** (release, Apple Silicon), **3× faster** than
  the Montgomery ladder for public-key derivation. Closes the
  Noise_IK gap entirely (1.24× → 0.98×).
- Perf gate: `gnet-crypto/tests/perf_gate.rs` →
  `x25519_basepoint_derivation_within_budget` (7 µs cap).

---

## Phase 2 — ML-KEM-768 polish (highest absolute ROI)

**Current state (2026-05-27 after T-2.1/T-2.4 + sha3 batched squeeze)**:
- decaps: ~1.03 (was 1.17) — essentially at parity, cap ratchetted to 1.15
- encaps: ~1.55 (was 1.62) — marginal, cap ratchetted to 1.75
- keygen: ~1.85 (was 1.88) — marginal, cap ratchetted to 2.10

T-2.2/T-2.3 (precomputed ZETAS, Montgomery/Barrett reductions) were
already implemented from day one — verified against FIPS 203 reference
and KAT'd by `ntt_mul_matches_schoolbook`. The remaining encaps / keygen
gap is dominated by **Keccak-f1600 throughput in matrix generation**: 9
`sample_ntt` calls × ~3 Keccak permutations each = 27 Keccak/keygen, all
in the scalar path. RustCrypto's `ml-kem` uses platform-tuned Keccak
(potentially Keccak-x4 / Keccak-x2 batching the matrix's parallel
streams). Closing the rest needs T-2.5 (SIMD NTT + batched Keccak).

### T-2.1 Audit current mlkem layout

- Dir: `crates/gnet-crypto/src/mlkem/`
- Map the pipeline: keygen → polynomial gen → NTT → matrix mul → noise
  sampling → compression. Identify which step dominates time (`cargo
  flamegraph` or `--emit asm` + manual count).
- Compare with `ml-kem` crate (RustCrypto): look at `src/ntt.rs`,
  `src/kemeleon.rs`, `src/lib.rs`. Catalogue the techniques they use
  (precomputed zeta tables for forward + inverse NTT, Montgomery
  reduction, vectorised polynomial add/sub).

### T-2.2 Precomputed zeta tables for NTT

- ML-KEM's NTT runs over Z_q[X] / (X^256 + 1) with q = 3329. The
  forward NTT needs 128 zeta multiplications per polynomial; precompute
  the 128 zetas as a `const [i16; 128]` at compile time.
- Same for inverse NTT (multiply by zeta_inv values).
- Reference (technique only): `ml-kem` crate's `ZETA` constant. Re-derive
  ours from FIPS 203 §A.1 to keep the code 100% original.
- Acceptance: keygen ratio drops 30%+.

### T-2.3 Montgomery reduction for modular arithmetic

- Replace `% 3329` with Montgomery-form multiplication. Standard
  technique for prime moduli on this size.
- Acceptance: encaps + decaps ratios drop 20%+.

### T-2.4 In-place polynomial ops

- Audit `Polynomial` ops in `mlkem/poly.rs` (or wherever): `add`, `sub`,
  `mul`. Each should mutate in-place into a caller-supplied buffer; no
  intermediate `Vec`.
- Acceptance: encaps + decaps ratios drop 10%+.

### T-2.5 (Stretch) Keccak-x4 NEON + NTT SIMD — DONE 2026-05-27 (partial)

**Keccak-x4 NEON** (commit 563734f):
- `crates/gnet-crypto/src/sha3/{mod,scalar,neon_x4}.rs`. Four 25-lane
  Keccak-f[1600] states packed across `(uint64x2_t lo, uint64x2_t hi)`
  per lane; ρ/π via macro-expanded constant rotates. Verified bit-exact
  vs scalar (`keccak_f_x4_matches_scalar` over 16 random quad-states).
- ML-KEM matrix gen routes 9 sample_ntt as 2 × 4-way + 1 scalar.
- Microbench (M4 Pro): `sample_ntt_x4` 1.66× faster than 4 serial
  scalar calls — limited by spilling the 50-register working set onto
  NEON's 32 physical registers.

**NTT/invNTT/ntt_mul NEON 8-way** (this commit):
- `crates/gnet-crypto/src/mlkem/ntt.rs` + inline `neon` mod. Outer 5
  butterfly layers (`len` ≥ 8) SIMD via `int16x8_t`; inner 2 layers
  (`len` = 2, 4) stay scalar. Forward NTT 1.14×, invNTT 1.25×, ntt_mul
  1.42× speedup vs scalar (Apple M4 Pro). Verified bit-exact via
  `ntt_neon_matches_scalar` + `ntt_mul_neon_matches_scalar` (32 random
  inputs each) and the schoolbook KAT (`ntt_mul_matches_schoolbook`).

**Serialize fast paths + fair RNG bench harness** (commit 3):
- `byte_encode` / `byte_decode` previously did LSB-by-LSB bit packing,
  ≈ 12 ops per coefficient at `d = 12`. Replaced with packed paths
  for `d ∈ {12, 10, 4, 1}` (2-coeff or 4-coeff stride, 3 ops/coeff)
  in `crates/gnet-crypto/src/mlkem/serialize.rs`. Generic LSB-by-LSB
  loop retained as fallback for unsupported `d` values (used only by
  tests). Saves ~10 µs / keygen and ~similar / encaps + decaps.
- Perf-gate harness previously interleaved `gnet_rand::fill` (~22 µs
  per call on macOS getrandom) into the gnet loop while the
  competitor's internal RNG made fewer syscalls — inflating the
  apparent gnet ratio. Replaced TestRng with a deterministic
  splitmix64-driven non-syscall RNG; both sides now compare
  algorithmic cost only.

**Apple median (5 runs) after T-2.5 + serialize + harness fix**:
- mlkem_keygen: 1.85 → 0.55 (cap ratchet aarch64 → 0.70)
- mlkem_encaps: 1.63 → 0.55 (cap ratchet aarch64 → 0.65)
- mlkem_decaps: 1.17 → 0.45 (cap ratchet aarch64 → 0.60)

**lx64 median (3 runs)** (serialize wins port to scalar; NEON paths
still stub to scalar fallback):
- mlkem_keygen: 1.60 → 0.69 (cap ratchet x86_64 → 0.85)
- mlkem_encaps: 1.35 → 0.74 (cap ratchet x86_64 → 0.85)
- mlkem_decaps: 1.17 → 0.67 (cap ratchet x86_64 → 0.80)

**Acceptance status**: original spec asked keygen drop 30%+ (target
< 1.30) and encaps drop 25%+ (target < 1.20). **All three ops now
winning by 1.4×–2.2× across both architectures.** Spec target
exceeded — T-2.5 fully DONE.

Reflection on why T-2.5 looked partial before: the perceived "1.54
keygen / 1.48 encaps" plateau after Keccak-x4 + NTT SIMD was a
combination of two things — `byte_encode`/`byte_decode` was the
unrecognized dominant cost (more time than gen_matrix + NTT
combined), and the bench harness asymmetrically inflated the gnet
side via macOS getrandom. Once both were addressed, the
algorithmic wins from Keccak-x4 + NTT SIMD compounded with the
serialize fast paths to land all three ops well below cap.

### Tighten gates

- After T-2.4 lands: ratchet to current observed +noise margin
  → `mlkem_keygen_hardgate` `max_ratio` `2.5` → `2.10`
  → `mlkem_encaps_hardgate` `max_ratio` `2.2` → `1.75`
  → `mlkem_decaps_hardgate` `max_ratio` `1.7` → `1.15`.
- After T-2.5 lands: ratchet to current measured + ~10% margin.
  → DONE 2026-05-27 (post-serialize): arch-cfg aarch64 caps
  0.70 / 0.65 / 0.60; x86_64 caps 0.85 / 0.85 / 0.80. All three
  ops now winning vs RustCrypto across both architectures.

(Re-bench after every sub-task; tighten the gate by the observed delta
to lock the win in.)

---

## Phase 3 — Verify and ratchet

### T-3.1 Re-run full cross-ecosystem comparison

- `cargo bench -p gnet-bench-compare` on both Apple Silicon and lx64.
- Update `README.md` Baseline table with the new numbers + date.
- Mark every category as "gnet ≥ competitor".

### T-3.2 Tighten remaining hardgate caps

- For categories that we're already winning (X25519, AEAD, hex):
  drop the cap to `1.05` to lock in the win against future regressions.

### T-3.3 Add direct-init upgrade path for relayed peers (carry-over)

- This was noted in the v0.5 path-selection commit body — periodically
  retry direct/punch on relayed peers to downgrade the relay hop when
  topology allows. Belongs in this polish round because it directly
  affects perceived data-plane latency.
- File: `crates/gnet/src/node.rs` maintenance thread.

---

## Phase 4 (stretch) — Cross-language comparison

Out of scope for the current ratchet; do once Rust-vs-Rust is settled
to keep the comparison meaningful.

### T-4.1 Go SOTA bench program

- New `crates/gnet-bench-compare/go/`
- Standalone `main.go` running:
  - `crypto/ecdh` (X25519)
  - `crypto/mlkem` (Go 1.24+)
  - `golang.org/x/crypto/chacha20poly1305`
  - `crypto/sha3` (BLAKE2 not in stdlib; skip or use `golang.org/x/crypto/blake2s`)
  - `encoding/hex`
- Output the same `ns/op` table format as the Rust benches.
- Document in `README.md` "Cross-language" section.

### T-4.2 C SOTA bench program

- New `crates/gnet-bench-compare/c/`
- Standalone `main.c` linking against `libsodium`:
  - `crypto_scalarmult_curve25519` (X25519)
  - `crypto_aead_chacha20poly1305_ietf_encrypt` (AEAD)
  - `crypto_kx` for handshake comparison? (no clean Noise_IK in libsodium)
  - `sodium_bin2hex` / `sodium_hex2bin`
- `Makefile` to build + run.

### T-4.3 Document end-to-end Mbps / pps

- `crates/gnet/scripts/netns-throughput.sh`
- Two netns daemons + `iperf3` through the tunnel, measure pps + Mbps.
- Compare with bare-loopback `iperf3` to see overhead.
- Compare with wireguard-go through netns same topology.
