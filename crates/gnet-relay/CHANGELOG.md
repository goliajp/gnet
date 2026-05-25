# Changelog

All notable changes to `mesh-relay` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Initial relay envelope codec: `encode_into` (allocation-free), `encode`
  (owned convenience), `decode` (borrowing), and `dst_key` (forward-only fast
  path). Envelope is `src_pubkey(32) ‖ dst_pubkey(32) ‖ inner`, where the inner
  datagram is opaque and stays end-to-end encrypted — the relay routes on
  `dst_key` without ever decrypting.
- Zero dependencies; `#![forbid(unsafe_code)]`.
- Hand-rolled `std::time` throughput benchmark (`benches/envelope.rs`) and a
  randomized roundtrip property test driven by the sibling `mesh-rand` (no
  external test crates).
- `BUDGETS.md` performance baseline + `tests/perf_gate.rs` regression gate.
