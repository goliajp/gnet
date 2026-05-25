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
| X25519 scalarmult | 27.3k ops/s · 36.6 µs | 52.1k ops/s · 19.2 µs | handshake |
| ML-KEM-768 keygen | 15.9k ops/s · 62.9 µs | 47.4k ops/s · 21.1 µs | handshake |
| ML-KEM-768 encaps | 20.2k ops/s · 49.5 µs | 48.9k ops/s · 20.5 µs | handshake |
| ML-KEM-768 decaps | 14.6k ops/s · 68.5 µs | 35.3k ops/s · 28.3 µs | handshake |

## Path taxonomy

- **Hot (per packet):** `aead::seal_in_place` / `open_in_place`. The only
  per-packet crypto on the data plane. At ≥ 7 Gbps/core it saturates 1–10 GbE.
  This is the path the regression gate guards.
- **Handshake-only (per session):** X25519 (×2), ML-KEM-768 keygen/encaps/
  decaps, BLAKE2s, SHA3/SHAKE. Runs once at session setup — the full ML-KEM
  trio is ~70 µs (Apple Silicon) / ~180 µs (lx64) — then never again. Not on
  the latency-sensitive path, so deliberately **not** optimized further:
  vectorizing the NTT could win 2–4× but buys nothing user-visible.

## Regression gates

`tests/perf_gate.rs` asserts the hot path stays within an order of magnitude of
baseline — a generous budget that catches a ~6–7× regression while tolerating
slow / contended CI. Runs in the normal `cargo test -p gnet-crypto`. The budget
tracks the build mode (unoptimized `cargo test` runs the crypto ~60× slower
than `--release`), so it is meaningful either way: 1000 µs/packet round-trip in
debug, 20 µs in release.

Rule: never weaken a budget without re-measuring P95 and justifying it in the
commit message.
