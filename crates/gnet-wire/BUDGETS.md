# gnet-wire performance budgets

Baselines from `cargo bench -p gnet-wire` (release, single core). The
transport-header stamp/read + `parse` demux run on every packet; `frame` and the
address codec are handshake- / discovery-rate. These are the yardstick we polish
against and the basis for the gate in `tests/perf_gate.rs`.

## Baseline (2026-05-25)

| op | lx64 (x86_64) | mac (Apple Silicon) | path |
|----|--------------:|--------------------:|------|
| put_index + put_counter | 1.26 ns/op | 1.08 ns/op | HOT (per-packet stamp) |
| index + counter (read) | 1.62 ns/op | 0.95 ns/op | HOT (per-packet read) |
| parse (tag demux) | 1.00 ns/op | 0.64 ns/op | HOT (per-packet) |
| frame (owned) | 8.98 ns/op | 13.30 ns/op | handshake (allocates) |
| encode_addr (v4) | 11.07 ns/op | 11.89 ns/op | endpoint discovery (allocates) |
| decode_addr (v4) | 2.21 ns/op | 2.26 ns/op | endpoint discovery |

## Notes

- The **transport path is allocation-free**: `put_*` / readers touch fields in
  place in the same buffer the ciphertext occupies. At ~1–2 ns/op the framing is
  a rounding error next to the AEAD seal (`gnet-crypto` ~1.2 µs/packet) — it will
  never be the data-plane bottleneck.
- `frame` and `encode_addr` allocate a small `Vec`, but both are off the data
  plane (handshake / endpoint discovery), so the allocation is acceptable.

## Regression gate

`tests/perf_gate.rs` asserts the per-packet transport-header stamp+read stays
under **500 ns/op** — generous enough for the unoptimized `cargo test` build and
slow CI while catching a gross regression. Never weaken without re-measuring and
justifying it in the commit message.
