# gnet-noise performance budgets

Baselines from `cargo bench -p gnet-noise` (release, single core). The Noise_IK
handshake runs once per session establishment — a warm path (several X25519
Diffie-Hellmans plus the symmetric ratchet), not per-packet. It is the yardstick
we polish against and the basis for the gate in `tests/perf_gate.rs`.

## Baseline (2026-05-25)

| op | lx64 (x86_64) | mac (Apple Silicon) | path |
|----|--------------:|--------------------:|------|
| Noise_IK full handshake | 482 µs/op | 251 µs/op | WARM (per session) |
| hybrid handshake (+ ML-KEM-768) | 612 µs/op | 306 µs/op | WARM (per session) |

(One complete initiator<->responder exchange: msg1 + read1 + msg2 + read2 +
split. The hybrid row is the same exchange plus an ML-KEM-768 encaps on the
initiator and decaps on the responder.)

## Notes

- The handshake is dominated by the X25519 Diffie-Hellmans in `gnet-crypto`. It
  runs once when a session comes up, never on the data plane, so the µs cost is
  amortized over the whole connection's traffic.
- The `hybrid` variant layers an ML-KEM-768 encaps/decaps on top (post-quantum
  KEM), adding ~60–140 µs. It is the handshake `gnet` actually runs, so it is
  benched and gated here alongside Noise_IK.

## Regression gate

`tests/perf_gate.rs` asserts a full Noise_IK handshake stays under **20 ms**
(measured ~3.6 ms lx64 / ~4.1 ms mac) and a full hybrid handshake under
**40 ms** (measured ~8.0 ms lx64 / ~7.1 ms mac) in the unoptimized `cargo test`
build — generous for slow CI while still catching a gross regression. Never
weaken without re-measuring and justifying it in the commit message.
