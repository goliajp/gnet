# gnet-bench-compare

Side-by-side perf comparison of gnet's hand-rolled, zero-dependency crypto
stones against the state-of-the-art Rust crates that own each category.
**Internal-only crate — `publish = false` — exists solely to put numbers next
to ours.** The production gnet stack stays at zero external Rust dependencies;
this comparison shop pulls competitors as dev-deps inside this single crate.

## Why this exists

The user-facing question is "is your hand-rolled crypto fast enough to ship?"
The answer needs numbers, not assertions. This crate produces those numbers:
each bench runs the gnet impl and the SOTA competitor impl on identical input
on the same CPU in the same `cargo bench` invocation, and prints a relative
multiplier so you can read the table in seconds.

## Coverage

| Category | gnet stone | Rust SOTA competitor |
|---|---|---|
| X25519 scalar mult | `gnet-crypto::x25519` | `x25519-dalek` (dalek-cryptography) |
| ChaCha20-Poly1305 | `gnet-crypto::aead` | `chacha20poly1305` (RustCrypto) |
| ML-KEM-768 | `gnet-crypto::mlkem` | `ml-kem` (RustCrypto) |
| Noise_IK handshake | `gnet-noise::handshake` | `snow` (mcginty) |
| Hex codec | `gnet-hex` | `hex` (rust-lang-deprecated, de-facto std) |

## Baseline (refreshed 2026-05-27 after Phase 1 + Phase 2 + T-1.4 + T-2.5)

Run: `cargo bench -p gnet-bench-compare`. Each line prints `ns/op` and a
relative multiplier (`<1× = competitor faster`, `>1× = competitor slower`).

### Apple Silicon (M-series)

| Op | gnet | competitor | gnet vs SOTA |
|----|-----:|-----------:|:------------:|
| X25519 (one ECDH) | 19.2 µs | 20.5 µs (dalek) | **1.07× faster** |
| AEAD seal in-place 1400B | 1.49 µs | 2.30 µs (RustCrypto) | **1.54× faster** |
| AEAD open in-place 1400B | 1.47 µs | 2.30 µs (RustCrypto) | **1.56× faster** |
| ML-KEM keygen | 11.7 µs | 22.0 µs (RustCrypto) | **1.82× faster** ← T-2.5 + serialize |
| ML-KEM encaps |  9.9 µs | 18.0 µs (RustCrypto) | **1.82× faster** ← T-2.5 + serialize |
| ML-KEM decaps | 10.9 µs | 24.2 µs (RustCrypto) | **2.22× faster** ← T-2.5 + serialize |
| X25519 basepoint derivation (`x25519_base`) | 5.4 µs | ~5 µs (dalek table) | **0.93× (slower 1.08×)** ← width-5 comb |
| Noise_IK handshake (classic) | 209 µs | 230 µs (snow) | **1.10× faster** ← + batch-invert |
| Noise_IK + ML-KEM (hybrid) | ~280 µs | — (no peer) | reference only |
| Hex encode 32 B | 32 ns | 58 ns (hex crate) | **1.82× faster** |
| Hex decode 32 B | 22 ns | 28 ns (hex crate) | **1.27× faster** |

### lx64 (Linux, x86_64 AVX2)

| Op | gnet | competitor | gnet vs SOTA |
|----|-----:|-----------:|:------------:|
| X25519 (one ECDH, Montgomery ladder) | 37.0 µs | 42.1 µs (dalek) | **1.14× faster** |
| X25519 basepoint derivation (`x25519_base`) | 9.9 µs | — (no apples-to-apples in dalek's perf suite) | ← width-5 comb |
| AEAD seal in-place 1400B | 1.22 µs | 2.04 µs (RustCrypto) | **1.68× faster** |
| AEAD open in-place 1400B | 1.20 µs | 2.02 µs (RustCrypto) | **1.69× faster** |
| ML-KEM keygen | 31.0 µs | 45.3 µs (RustCrypto) | **1.45× faster** ← T-2.5 + serialize |
| ML-KEM encaps | 31.6 µs | 42.8 µs (RustCrypto) | **1.35× faster** ← T-2.5 + serialize |
| ML-KEM decaps | 37.0 µs | 55.2 µs (RustCrypto) | **1.49× faster** ← T-2.5 + serialize |
| Noise_IK handshake (classic) | 364 µs | 416 µs (snow) | **1.14× faster** ← + batch-invert |
| Noise_IK + ML-KEM (hybrid) | ~480 µs | — | reference only |
| Hex encode 32 B | 45 ns | 94 ns (hex crate) | **2.06× faster** |
| Hex decode 32 B | 49 ns | 51 ns (hex crate) | **1.05× faster** |

## Read this table in 30 seconds

**Where gnet beats or matches the Rust SOTA (10 categories on Apple — all benched):**

- **Hex codec**: 1.27×–1.82× faster than the `hex` crate. The `hex`
  crate has a generic API surface (multiple decode targets, error
  types); gnet-hex is a single-purpose `Vec<u8>` / `[u8; 32]` impl that
  the optimiser handles better.
- **AEAD seal / open**: 1.5×–1.7× faster than RustCrypto's
  `chacha20poly1305`. Both are constant-time pure Rust; gnet's impl
  uses a tighter Poly1305 inner loop and avoids the trait-object
  indirection RustCrypto layers add.
- **X25519**: 1.07×–1.19× faster than `x25519-dalek` on general ECDH.
- **ML-KEM (all three ops)**: gnet now **1.82×–2.22× faster** than
  RustCrypto's `ml-kem` on Apple (1.35–1.49× on lx64). Breakdown of
  what got us here:
  1. **Phase 2 polish** (in-place poly ops, lane-aligned SHAKE squeeze)
     — closed the initial 1.7×–1.9× gap to ~parity on decaps.
  2. **T-2.5 Keccak-x4 NEON + NTT/invNTT/ntt_mul NEON 8-way** —
     real algorithmic improvements on aarch64.
  3. **`byte_encode` / `byte_decode` fast paths** for `d ∈ {12, 10, 4, 1}`
     — replaced the LSB-by-LSB bit loop (12 ops/coeff) with a packed
     2-coeff or 4-coeff inner loop (≈ 3 ops/coeff). This was the
     unrecognized dominant cost across all three ops: ~10 µs / call.
  4. **Fair bench harness**: the perf-gate previously interleaved
     `gnet_rand::fill` (≈ 22 µs / call on macOS getrandom) into the
     gnet loop while the competitor's internal RNG made a different
     number of syscalls, inflating gnet's apparent ratio by ~2×.
     Both sides now use a deterministic non-syscall `TestRng`, so the
     ratio reflects algorithmic cost only.
- **Noise_IK handshake (classic)**: **1.10× faster** than `snow` on
  Apple, **1.14× faster** on lx64 (was 1.24× / 1.14× slower at the
  2026-05-27 baseline). Three stones got us here:
    1. Phase 1 allocation polish (allocation-free `Hasher` + HKDF,
       single-Vec output) trimmed the per-handshake overhead.
    2. T-1.4 + width-5 Edwards-basepoint comb cut public-key
       derivation from ~20 µs (Montgomery ladder) to **~5.4 µs**
       on Apple / **~9.9 µs** on lx64.
    3. `x25519_base_pair` batch-inversion shares one Curve25519
       field inversion between the static + ephemeral derivations
       inside `Initiator::new` / `Responder::new`, saving another
       ≈ 2 µs per side per handshake on Apple.

**Where gnet is still marginally slower (1 category on Apple, near-parity):**
- **X25519 basepoint derivation**: 1.08× slower than `x25519-dalek`'s
  `EdwardsBasepointTable` (5.4 µs vs ~5 µs). We use a width-5 comb
  with ~97 KiB rodata (52 windows × 16 entries). The remaining ~400 ns
  gap is in the finvert chain inside `ed_to_mont_u` — a per-call
  inversion that dalek also pays. Closing it further would require
  batched inversion across multiple `x25519_base` calls in the same
  handshake, which is invasive on the gnet-noise API surface.

## How to read the numbers operationally

- Per-handshake budget: ~5–10 ms is "fast" for an interactive overlay.
  gnet's hybrid handshake at 356–620 µs sits at 4–6% of that budget;
  after T-2.5 + serialize fast paths the ML-KEM trio takes ≈ 32 µs
  on Apple Silicon (was ≈ 130 µs at baseline).
- Per-packet budget at MTU 1400: at 1 Gbps line rate that's ~89k pps
  per direction. gnet's AEAD at 1.2–1.5 µs/op leaves ample headroom
  (rough ceiling ~700k pps from AEAD alone — bottleneck is elsewhere).
- Hex is a once-per-handshake cost; either impl is dwarfed by the
  network round-trip by 4 orders of magnitude.

## Reproducing

```bash
cargo bench -p gnet-bench-compare           # all five benches
cargo bench -p gnet-bench-compare --bench x25519
cargo bench -p gnet-bench-compare --bench chacha20poly1305
cargo bench -p gnet-bench-compare --bench mlkem
cargo bench -p gnet-bench-compare --bench noise
cargo bench -p gnet-bench-compare --bench hex
```

Each bench is hand-rolled `std::time` (no criterion dep here either) and
prints a one-shot table — no per-iteration noise reduction, so individual
runs can vary 5–15%. Run several times and look at the median if you need a
tight number; the 30-second take-away from this README is the order of
magnitude and direction.

## Cross-language reference

Per-op timings against the most-common non-Rust implementations a
GOLIA-network operator would otherwise reach for: **Go stdlib** (`crypto/ecdh`,
`crypto/mlkem`, `crypto/sha3` + `golang.org/x/crypto`) and **libsodium**
(`crypto_scalarmult_curve25519`, `crypto_aead_chacha20poly1305_ietf_*`,
`sodium_bin2hex`, `crypto_generichash`). Same best-of-10 sampling protocol
as the Rust gate, so the ratios cancel hardware noise.

### Apple Silicon (M4 Pro, aarch64) — 2026-05-28

| 类别 | gnet | RustCrypto | Go stdlib | libsodium |
|---|---:|---:|---:|---:|
| X25519 ECDH | **18.3 µs** | 20.7 µs | 23.6 µs | 20.0 µs |
| AEAD seal 1400B | 1.37 µs | 2.27 µs | **1.25 µs** | 2.03 µs |
| AEAD open 1400B | 1.37 µs | 2.26 µs | **1.28 µs** | 2.14 µs |
| ML-KEM keygen | **9.85 µs** | 21.7 µs | 27.9 µs | — |
| ML-KEM encaps | **9.79 µs** | 18.6 µs | 27.2 µs | — |
| ML-KEM decaps | **10.9 µs** | 24.4 µs | 35.7 µs | — |
| Hex encode 32B | 29.8 ns | 77.1 ns | 38.7 ns | **19.5 ns** |
| Hex decode 32B | **21.8 ns** | 26.1 ns | 28.6 ns | 58.2 ns |
| BLAKE2s-256 64B | (gnet only) | — | 122.6 ns | — (BLAKE2b 114 ns) |

### lx64 (Intel i7-10700K Comet Lake, AVX2) — 2026-05-28

| 类别 | gnet | RustCrypto | Go stdlib |
|---|---:|---:|---:|
| AEAD seal 1400B | 1.20 µs | 2.00 µs | **0.63 µs** |
| AEAD open 1400B | 1.20 µs | 2.02 µs | **0.61 µs** |
| ML-KEM keygen | **18.8 µs** | 44.7 µs | 47.7 µs |
| ML-KEM encaps | **16.9 µs** | 42.0 µs | 50.7 µs |
| ML-KEM decaps | **19.8 µs** | 54.1 µs | 67.6 µs |

**Honest reading**

- gnet wins **5 of 8** comparable categories on Apple Silicon.
- gnet wins ML-KEM by ~2-3× against every alternative — the v0.8 AVX2/NEON
  work compounded with `byte_encode` fast paths and the in-house
  Keccak-x4 makes the gap structural, not transient.
- gnet **trails ChaCha20-Poly1305 AEAD vs Go stdlib by ~7-9% (down from
  ~14-16%)**. The v0.9 intrinsic-schedule pre-flight (independent SSA
  locals in the ChaCha20 NEON path + `vpaddq_u64`-based Poly1305 hsum)
  closed roughly a third of the open gap and met the ≤8% target on
  `open`; `seal` sits at 9% and is bounded by the ARMv8 NEON register
  pressure ceiling LLVM hits on the 4-way ChaCha20 round (35 live
  vector values > 32 physical NEON registers, with 6 spills inside
  the inner round body). Further closure would require dropping
  to inline assembly — see [ASM_NOTES.md](ASM_NOTES.md) for the cost
  study and the v0.9 measured-result update at the bottom.
- gnet **loses 53% on hex encode vs libsodium** (and 31% vs Go). libsodium's
  `sodium_bin2hex` uses bytewise SWAR + table lookup; the gain here is
  small absolute (10 ns) and a cold path (per-config-line, not per-packet),
  so not a polish priority.
- **lx64 AEAD AVX2 trails Go stdlib by ~90% (1.20 µs vs 0.63 µs)** — far
  worse than the ~7-9% Apple ARM64 gap. x86_64 AVX2 has only 16 physical
  YMM registers vs ARM64 NEON's 32, while the 8-way ChaCha20 layout needs
  16 state + 16 init = 32 logical vectors live simultaneously. LLVM
  spills half the working set to stack every inner round (`subq $1608,
  %rsp`, 9 spill slots inside the round body), and Go's `chacha_amd64.s`
  + `sum_amd64.s` hand-rolled assembly side-steps this with manually
  scheduled register tiling. The v0.10 pre-flight verified independent
  SSA locals do not help on x86_64 (0.2–0.4% regression, ceiling is
  physical not analytic) — see [ASM_NOTES.md](ASM_NOTES.md) v0.10
  section for the data + decision update.

Reproduce:

```sh
# Go (requires Go 1.24+ for crypto/mlkem)
cd crates/gnet-bench-compare/go && go run ./...

# C / libsodium (brew install libsodium  /  apt install libsodium-dev)
cd crates/gnet-bench-compare/c && make run
```

## Out-of-scope (intentional)

- **End-to-end throughput (Mbps over TUN)**: belongs in a netns scripts /
  `iperf3` harness, not a micro-bench. See `crates/gnet/scripts/netns-*.sh`
  for the existing E2E correctness tests; throughput E2E is future work.

## Where to look if a row is surprising

- **gnet** sources: `crates/gnet-crypto/src/{x25519,aead,mlkem,chacha20,poly1305,blake2s}.rs`,
  `crates/gnet-noise/src/{handshake,hybrid}.rs`, `crates/gnet-hex/src/lib.rs`.
- **Competitors**: pinned in `Cargo.toml` at the workspace level —
  `x25519-dalek`, `chacha20poly1305`, `snow`, plus `ml-kem` and `hex`
  pinned here.
