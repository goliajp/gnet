# Changelog

All notable changes to `gnet-noise` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `gnet` into a standalone zero-dependency stone: the
  `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake (the pattern WireGuard uses),
  built bottom-up on the in-house `gnet-crypto` primitives — `cipher_state`
  (AEAD key + nonce), `symmetric_state` (chaining key + transcript hash +
  cipher), and the `handshake` initiator / responder state machines. A `hybrid`
  variant layers the ML-KEM-768 KEM over Noise_IK for post-quantum forward
  secrecy. Ephemeral keys are injected by the caller (no RNG dependency).
- Hand-rolled `std::time` handshake benchmark (`benches/handshake.rs`), a
  `tests/perf_gate.rs` regression gate, and a `BUDGETS.md` baseline.
- README, dual LICENSE, crates.io metadata. Zero external crates.
- Hybrid (Noise_IK + ML-KEM-768) handshake bench + perf_gate (40 ms budget) +
  BUDGETS row. The hybrid handshake is the one `gnet` actually runs;
  previously only the classical Noise_IK path was benched and gated.
