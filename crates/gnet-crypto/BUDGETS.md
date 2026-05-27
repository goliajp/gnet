# gnet-crypto performance budgets

Baselines from `cargo bench -p gnet-crypto` (release, single core). These are
the yardstick we polish against and the basis for the regression gates in
`tests/perf_gate.rs`.

## Baseline (2026-05-25)

| primitive | lx64 (x86_64 AVX2) | mac (Apple Silicon NEON) | path |
|-----------|-------------------:|-------------------------:|------|
| ChaCha20 keystream | 2935 MiB/s | 1431 MiB/s | hot (component) |
| Poly1305 MAC | 4063 MiB/s | 3371 MiB/s | hot (component) |
| BLAKE2s hash | 458 MiB/s | 617 MiB/s | handshake |
| ChaCha20-Poly1305 seal (alloc) | 1669 MiB/s | 970 MiB/s | — |
| AEAD seal_in_place 64K | 1722 MiB/s | 854 MiB/s | bulk |
| **AEAD seal_in_place 1400B** | **1132 MiB/s · 9.2 Gbps · 1179 ns/pkt** | **913 MiB/s · 7.3 Gbps · 1462 ns/pkt** | **HOT (per packet)** |
| X25519 scalarmult (variable point) | 27.3k ops/s · 36.6 µs | 52.1k ops/s · 19.2 µs | handshake |
| **X25519 basepoint derivation (width-5 comb)** | **100k ops/s · 9.9 µs** | **185k ops/s · 5.4 µs** | handshake (×4 / hybrid) |
| ML-KEM-768 keygen (pre-T-2.5) | 15.9k ops/s · 62.9 µs | 47.4k ops/s · 21.1 µs | handshake |
| ML-KEM-768 encaps (pre-T-2.5) | 20.2k ops/s · 49.5 µs | 48.9k ops/s · 20.5 µs | handshake |
| ML-KEM-768 decaps (pre-T-2.5) | 14.6k ops/s · 68.5 µs | 35.3k ops/s · 28.3 µs | handshake |
| **ML-KEM-768 keygen** (T-2.5 + serialize) | **31.0 µs · 32.3k ops/s** | **11.7 µs · 85.5k ops/s** | handshake |
| **ML-KEM-768 encaps** (T-2.5 + serialize) | **31.6 µs · 31.6k ops/s** | **9.9 µs · 101k ops/s** | handshake |
| **ML-KEM-768 decaps** (T-2.5 + serialize) | **37.0 µs · 27.0k ops/s** | **10.9 µs · 91.7k ops/s** | handshake |
| `byte_encode` d=12 (scalar fast path) | tbd | ~700 ns / 256-coeff poly | ek/dk serialize |
| `byte_encode` d=10 (scalar fast path) | tbd | ~400 ns / 256-coeff poly | u ciphertext serialize |
| Keccak-f[1600] scalar permutation | tbd | 185 ns/perm (M4 Pro) | SHA-3 / SHAKE base |
| `sample_ntt` (scalar) | tbd | 643 ns/poly | ML-KEM matrix gen |
| `sample_ntt_x4` (NEON 4-way) | (scalar) | 388 ns/poly (1.66× over 4× serial) | ML-KEM matrix gen |
| `ntt` forward (NEON 8-way) | (scalar) | 110 ns vs 125 ns scalar (1.14×) | ML-KEM |
| `invntt` (NEON 8-way + F-scale SIMD) | (scalar) | 190 ns vs 237 ns scalar (1.25×) | ML-KEM |
| `ntt_mul_into` (NEON 8-way) | (scalar) | 55 ns vs 78 ns scalar (1.42×) | ML-KEM |

## Path taxonomy

- **Hot (per packet):** `aead::seal_in_place` / `open_in_place`. The only
  per-packet crypto on the data plane. At ≥ 7 Gbps/core it saturates 1–10 GbE.
  This is the path the regression gate guards.
- **Handshake-only (per session):** X25519 (×2), ML-KEM-768 keygen/encaps/
  decaps, BLAKE2s, SHA3/SHAKE. Runs once at session setup — the full ML-KEM
  trio is ~70 µs (Apple Silicon) / ~180 µs (lx64) — then never again. Per
  handshake we now also amortize public-key derivation via the Edwards comb
  (`x25519_base`), which is invoked 4× per hybrid Noise_IK initiator
  (static + ephemeral on each side) so the 3× speedup over the ladder
  trims ≈ 50 µs of handshake latency.

## Regression gates

`tests/perf_gate.rs` asserts the hot path stays within an order of magnitude of
baseline — a generous budget that catches a ~6–7× regression while tolerating
slow / contended CI. Runs in the normal `cargo test -p gnet-crypto`. The budget
tracks the build mode (unoptimized `cargo test` runs the crypto ~60× slower
than `--release`), so it is meaningful either way: 1000 µs/packet round-trip in
debug, 20 µs in release for the AEAD path. The `x25519_basepoint_derivation`
gate covers public-key derivation at 7 µs/op release / 400 µs/op debug.

Rule: never weaken a budget without re-measuring P95 and justifying it in the
commit message.
