# gnet-hex performance budgets

Baselines from `cargo bench -p gnet-hex` (release, single core). Hex codec runs
wherever a pubkey crosses a textual boundary: `gnet keygen`, `gnet join` JSON,
`gnet status` operator dumps, conf parser, coordinator wire envelopes. The
32-byte (X25519) path is the dominant case — one encode + one decode per
join / status. The 1184-byte (ML-KEM-768 ek) path runs once per join.

## Baseline (2026-05-27)

| op | lx64 (x86_64) | mac (Apple Silicon) | path |
|----|--------------:|--------------------:|------|
| encode 32B → 64 hex | 42 ns/op | 32 ns/op | per-pubkey serialise |
| decode_32 (64 hex → 32B) | 47 ns/op | 22 ns/op | per-pubkey parse (fast path) |
| decode 32B (generic Vec) | 63 ns/op | 45 ns/op | conf parse `peer ... <ek-hex> ...` |
| encode 1184B (mlkem ek) | 1.2 µs/op | 0.8 µs/op | per-join JSON body |
| decode 1184B (mlkem ek) | 1.9 µs/op | 1.1 µs/op | per-peer-poll JSON parse |

## Notes

- The codec is allocation-bound: `encode` builds a `String::with_capacity`,
  `decode` builds a `Vec`. On the X25519 path that's a single 64-byte
  allocation — negligible. On the ML-KEM path that's ~1 KB, still negligible
  next to the ML-KEM keygen / decaps math itself (`gnet-crypto` ~100 µs).
- `decode_32` is faster than the generic `decode` because it writes into a
  stack-allocated `[u8; 32]`, no heap. Use it whenever the expected length is
  exactly 32 (X25519 keys).
- A `gnet status` call does ~10 hex encode/decode round-trips — under 1 µs
  total. The HTTP round-trip to the coordinator dominates by 4 orders of
  magnitude.

## Regression gate

`tests/perf_gate.rs` asserts `encode 32B` and `decode_32` stay under
**1500 ns/op** — ~30–70× the observed P95 (32–47 ns/op), generous for the
unoptimised `cargo test` build and slow CI but tight enough to catch a 10×
algorithmic regression. Never weaken without re-measuring and justifying
in the commit message.
