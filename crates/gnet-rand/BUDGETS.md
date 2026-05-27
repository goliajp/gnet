# gnet-rand performance budgets

Baselines from `cargo bench -p gnet-rand` (release, single core). Every entropy
draw is one read from `/dev/urandom`, so the floor is the syscall + file-open
+ kernel CSPRNG path — there is no algorithmic work to optimise here. We
benchmark anyway so a regression in entropy infrastructure (e.g. someone
swapping in a slower source) is caught.

## Baseline (2026-05-27)

| op | lx64 (x86_64) | mac (Apple Silicon) | path |
|----|--------------:|--------------------:|------|
| random_32 | 1354 ns/op | 7557 ns/op | handshake (X25519 scalar) |
| random_u32 | 1333 ns/op | 7290 ns/op | per-op tag (rx_index / probe txid / jitter) |
| fill 32B (stack) | 1338 ns/op | 7471 ns/op | (same syscall as random_32, no copy) |
| fill 1024B | 3156 ns/op | 8679 ns/op | ML-KEM keygen-from-entropy |

## Notes

- The per-op cost is dominated by `File::open("/dev/urandom") + read_exact` —
  the syscall + page-fault path is the floor, not the entropy generation.
- macOS is slower than Linux per-call (≈ 5.5×) due to the heavier `open` path
  on Darwin. Not a gnet-rand bug; both stay well under the per-handshake
  budget.
- A Noise_IK + ML-KEM handshake draws entropy ~5 times (ephemeral, rx_index,
  ML-KEM encaps randomness). At 8 µs/op on macOS that's 40 µs of entropy —
  rounding error next to ML-KEM ops at ~100 µs.

## Regression gate

`tests/perf_gate.rs` asserts `random_32` and `random_u32` stay under
**50 000 ns/op (= 50 µs/op)**: ~7× the observed P95 on macOS, ~37× on Linux.
Generous to absorb CI noise and the `cargo test` unoptimised build, strict
enough to catch a 10× regression. Never weaken without re-measuring and
justifying in the commit message.
