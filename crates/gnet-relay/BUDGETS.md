# mesh-relay performance budgets

Baselines from `cargo bench -p mesh-relay` (release, single core). The envelope
is on the relay data path: `encode_into` wraps every relayed packet on send,
`dst_key` routes it at the relay, `decode` unwraps it at the receiver. These are
the yardstick we polish against and the basis for the gate in
`tests/perf_gate.rs`.

## Baseline (2026-05-25)

| op | lx64 (x86_64) | mac (Apple Silicon) | path |
|----|--------------:|--------------------:|------|
| **encode_into 1400B** | **111.9k MiB/s · 12.5 ns/pkt** | **79.8k MiB/s · 17.5 ns/pkt** | **HOT (per relayed packet)** |
| decode (O(1) parse) | 1.2 ns/op | 0.9 ns/op | HOT (receiver unwrap) |
| dst_key (route only) | 0.6 ns/op | 0.5 ns/op | HOT (relay forward) |

## Notes

- **`encode_into`** is a `HEADER_LEN + inner` memcpy into the caller's send
  buffer (allocation-free). Its throughput tracks memory bandwidth — at ~100+
  GiB/s it is a rounding error next to the AEAD seal that produced the inner
  ciphertext (`mesh-crypto` ~1.1 GiB/s for the 1400B hot path). Relay wrapping
  is never the bottleneck.
- **`decode` / `dst_key`** are O(1) slice arithmetic — they borrow and never
  copy the payload, so their throughput figure is not meaningful; the **ns/op**
  is the indicator. `dst_key` is the relay's forward-only fast path: it reads a
  single 32-byte field to route, sub-nanosecond.

## Regression gate

`tests/perf_gate.rs` asserts `encode_into` stays under **1000 ns/op** — a
generous budget (~55× over the ~18 ns optimized baseline) that catches a gross
regression while tolerating the unoptimized `cargo test` build and slow CI. It
runs in the normal `cargo test -p mesh-relay`.

Rule: never weaken a budget without re-measuring and justifying it in the commit
message.
