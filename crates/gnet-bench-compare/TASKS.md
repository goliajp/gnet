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

## Phase 1 — Noise_IK overhead polish

**Current state (2026-05-27 after T-1.1/T-1.2/T-1.3 land)**: classic
Noise_IK handshake is ~1.25× (Apple) slower than `snow`. The state-
machine allocation/inline polish (T-1.2/T-1.3) trimmed the inner BLAKE2s
and HKDF allocations to zero; remaining gap is dominated by **X25519
basepoint multiplication**. We compute `static_pub` + `ephemeral_pub` per
side per handshake via a general scalar mult (~20µs each); snow uses
x25519-dalek's `EphemeralSecret`-style basepoint-with-precomputed-table
multiplication (~5µs each). Gap = 4 basepoint mults × ~15µs ≈ 60µs ≈
the entire 53µs gap.

**Hardgate cap now 1.35** (was 1.60); ratchet to 1.05 after T-1.4 lands.

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

### T-1.4 (follow-up) X25519 basepoint precomputation

- File: `crates/gnet-crypto/src/x25519.rs` + new `x25519/base_table.rs`
- Add `pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32]` using a
  fixed-base comb method with a compile-time-precomputed table
  (~16 KiB, e.g. 256 Edwards points). Route `Initiator::new` /
  `Responder::new` / `HybridInitiator::new` / `HybridResponder::new`
  `public_of` through it.
- Reference (technique only): curve25519-dalek's `EdwardsBasepointTable`
  comb — re-derive from FIPS 186-5 / RFC 7748 / Bernstein's
  donna-c64 to keep gnet 0-dep / 100%-original.
- Acceptance: classic Noise_IK hardgate ratio drops below 1.10
  (current ~1.25 → goal < 1.10). Likely well below 1.05 since the gap
  is ~60µs over a 217µs snow baseline.

### Tighten gate

- After T-1.3 lands (Phase 1 polish complete): ratchet
  `tests/perf_gate.rs` → `noise_ik_classic_hardgate` `max_ratio`
  from `1.60` → `1.35` (captures current state with noise margin).
- After T-1.4 lands: ratchet → `1.05`.

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

### T-2.5 (Stretch) Keccak-x4 NEON / NTT SIMD

- File: `crates/gnet-crypto/src/sha3.rs` + new `sha3/neon_x4.rs`
- ML-KEM-768 matrix generation can run 4 SHAKE128 streams in parallel
  (the i,j seeds are independent). With NEON we keep four 25-lane Keccak
  states in `uint64x2_t` pairs and run the 24 rounds 4-way.
- Reference (technique only): pqcrystals-kyber-aarch64-neon, FIPS 202.
  Re-derive ours; the permutation arithmetic is the same.
- Acceptance: keygen ratio drops 30%+ (target < 1.30); encaps drops
  25%+ (target < 1.20).

For NTT SIMD (separate sub-task): NEON 8-way i16 ops on the butterfly
inner loop. Acceptance: decaps + encaps drop another 15%+.

### Tighten gates

- After T-2.4 lands: ratchet to current observed +noise margin
  → `mlkem_keygen_hardgate` `max_ratio` `2.5` → `2.10`
  → `mlkem_encaps_hardgate` `max_ratio` `2.2` → `1.75`
  → `mlkem_decaps_hardgate` `max_ratio` `1.7` → `1.15`.
- After T-2.5 lands: ratchet all three to `1.05` (or below).

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
