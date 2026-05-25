# mesh-punch performance budgets

Baselines from `cargo bench -p mesh-punch` (release, single core). The
rendezvous codec + state transitions are setup-rate (a handful of calls per
punch), not per-packet, so these are cost-tracking baselines rather than
data-plane budgets.

## Baseline (2026-05-25)

| op | lx64 (x86_64) | mac (Apple Silicon) | path |
|----|--------------:|--------------------:|------|
| encode_connect | 11.88 ns/op | 16.72 ns/op | rendezvous setup (allocates Vec) |
| decode_connect | 3.73 ns/op | 3.70 ns/op | rendezvous setup |
| encode_sync | 7.26 ns/op | 13.33 ns/op | rendezvous setup (allocates Vec) |
| decode_sync | 2.70 ns/op | 2.71 ns/op | rendezvous setup |
| on_reply (RTT measure → Syncing) | 28.53 ns/op | 37.08 ns/op | one transition per punch |

## Notes

- Every entry runs only a handful of times per punch attempt (setup-rate), never
  per packet — so the `Vec` allocation in `encode_*` is acceptable and none of
  this is on the data plane. The numbers exist to catch a gross regression, not
  to chase nanoseconds.

## Regression gate

`tests/perf_gate.rs` asserts `encode_connect` stays under **2000 ns/op** —
generous for the unoptimized `cargo test` build + slow CI. Never weaken without
re-measuring and justifying it in the commit message.
