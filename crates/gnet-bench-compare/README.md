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

## Baseline (2026-05-27)

Run: `cargo bench -p gnet-bench-compare`. Each line prints `ns/op` and a
relative multiplier (`<1× = competitor faster`, `>1× = competitor slower`).

### Apple Silicon (M-series)

| Op | gnet | competitor | gnet vs SOTA |
|----|-----:|-----------:|:------------:|
| X25519 (one ECDH) | 19.1 µs | 20.7 µs (dalek) | **1.08× faster** |
| AEAD seal in-place 1400B | 1.49 µs | 2.25 µs (RustCrypto) | **1.51× faster** |
| AEAD open in-place 1400B | 1.47 µs | 2.27 µs (RustCrypto) | **1.55× faster** |
| ML-KEM keygen | 68.7 µs | 36.5 µs (RustCrypto) | 0.53× (slower 1.9×) |
| ML-KEM encaps | 43.6 µs | 26.9 µs (RustCrypto) | 0.62× (slower 1.6×) |
| ML-KEM decaps | 28.4 µs | 24.3 µs (RustCrypto) | 0.85× (slower 1.2×) |
| Noise_IK handshake (classic) | 266 µs | 219 µs (snow) | 0.82× (slower 1.2×) |
| Noise_IK + ML-KEM (hybrid) | 356 µs | — (no peer) | reference only |
| Hex encode 32 B | 32 ns | 79 ns (hex crate) | **2.42× faster** |
| Hex decode 32 B | 22 ns | 29 ns (hex crate) | **1.29× faster** |
| Hex encode 1184 B (mlkem ek) | 798 ns | 1997 ns (hex crate) | **2.50× faster** |
| Hex decode 1184 B (mlkem ek) | 1082 ns | 3128 ns (hex crate) | **2.89× faster** |

### AWS Tokyo aarch64 (Linux, lx64)

| Op | gnet | competitor | gnet vs SOTA |
|----|-----:|-----------:|:------------:|
| X25519 (one ECDH) | 36.6 µs | 43.6 µs (dalek) | **1.19× faster** |
| AEAD seal in-place 1400B | 1.20 µs | 1.99 µs (RustCrypto) | **1.66× faster** |
| AEAD open in-place 1400B | 1.20 µs | 2.02 µs (RustCrypto) | **1.68× faster** |
| ML-KEM keygen | 79.7 µs | 47.6 µs (RustCrypto) | 0.60× (slower 1.7×) |
| ML-KEM encaps | 63.1 µs | 43.1 µs (RustCrypto) | 0.68× (slower 1.5×) |
| ML-KEM decaps | 70.7 µs | 54.1 µs (RustCrypto) | 0.77× (slower 1.3×) |
| Noise_IK handshake (classic) | 464 µs | 409 µs (snow) | 0.88× (slower 1.1×) |
| Noise_IK + ML-KEM (hybrid) | 620 µs | — | reference only |
| Hex encode 32 B | 44 ns | 94 ns (hex crate) | **2.15× faster** |
| Hex decode 32 B | 48 ns | 51 ns (hex crate) | **1.08× faster** |
| Hex encode 1184 B | 1292 ns | 2912 ns (hex crate) | **2.25× faster** |
| Hex decode 1184 B | 1957 ns | 3119 ns (hex crate) | **1.59× faster** |

## Read this table in 30 seconds

**Where gnet beats the Rust SOTA (5 categories, both archs):**

- **Hex codec**: 1.1×–2.9× faster than the `hex` crate, on both encode and
  decode, both sizes. The `hex` crate has a generic API surface (multiple
  decode targets, error types); gnet-hex is a single-purpose `Vec<u8>` /
  `[u8; 32]` impl that the optimiser handles better.
- **AEAD seal / open**: 1.5×–1.7× faster than RustCrypto's
  `chacha20poly1305`. Both are constant-time pure Rust; gnet's impl
  uses a tighter Poly1305 inner loop and avoids the trait-object
  indirection RustCrypto layers add.
- **X25519**: 1.08×–1.19× faster than `x25519-dalek`. Slim margin —
  dalek is heavily optimised — but the hand-rolled scalar impl pulls
  ahead on commodity hardware.

**Where gnet is slower (2 categories):**

- **ML-KEM-768**: 1.2×–1.9× slower than RustCrypto's `ml-kem`.
  RustCrypto uses extensive precomputation tables and SIMD-friendly
  matrix ops; gnet-crypto is a NIST FIPS 203 reference impl. This is
  the single biggest opportunity for follow-up optimisation: ML-KEM
  dominates handshake cost.
- **Noise_IK handshake**: 1.1×–1.2× slower than `snow` on the classic
  path. The gap is entirely amortised across the ML-KEM step on the
  hybrid handshake (which has no peer to compare).

## How to read the numbers operationally

- Per-handshake budget: ~5–10 ms is "fast" for an interactive overlay.
  gnet's hybrid handshake at 356–620 µs sits at 4–6% of that budget.
  ML-KEM optimisation would shave the cost roughly in half, freeing
  budget for higher join concurrency.
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
