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
| Noise_IK handshake (classic) | 212 µs | 217 µs (snow) | **1.02× faster** ← T-1.4 win |
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
| Noise_IK handshake (classic) | 372 µs | 411 µs (snow) | **1.10× faster** ← T-1.4 win |
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
- **Noise_IK handshake (classic)**: **1.02× faster** than `snow` on
  Apple, **1.10× faster** on lx64 (was 1.24× / 1.14× slower at the
  2026-05-27 baseline). Phase 1 allocation polish trimmed the
  per-handshake overhead; T-1.4's Edwards basepoint comb cut
  public-key derivation from ~20 µs (Montgomery ladder) to ~5.4 µs
  on Apple / ~9.9 µs on lx64 (width-5 Edwards comb, T-1.4 + width-5
  refinement), saving ≈ 65 µs over the four `public_of` calls in a
  hybrid handshake.

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

## Out-of-scope (intentional)

- **Cross-language comparison (Go / C / kernel WireGuard)**: planned as a
  follow-up; would require either FFI or standalone `go test -bench` /
  `libsodium` micro-benchmark binaries. Both possible; not in this crate.
- **End-to-end throughput (Mbps over TUN)**: belongs in a netns scripts /
  `iperf3` harness, not a micro-bench. See `crates/gnet/scripts/netns-*.sh`
  for the existing E2E correctness tests; throughput E2E is future work.

## Where to look if a row is surprising

- **gnet** sources: `crates/gnet-crypto/src/{x25519,aead,mlkem,chacha20,poly1305,blake2s}.rs`,
  `crates/gnet-noise/src/{handshake,hybrid}.rs`, `crates/gnet-hex/src/lib.rs`.
- **Competitors**: pinned in `Cargo.toml` at the workspace level —
  `x25519-dalek`, `chacha20poly1305`, `snow`, plus `ml-kem` and `hex`
  pinned here.
