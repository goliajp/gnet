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
- `HYBRID.md` — full design rationale for the
  `Noise_pqIKhybrid_25519MLKEM768_ChaChaPoly_BLAKE2s` construction with
  paper-trail anchors (PQ-WireGuard 2021, Bindel et al. KEM combiners,
  Noise Framework rev 34, NIST FIPS 203 / SP 800-56C). Documents what the
  construction does *not* claim (no cross-implementation test vector at
  the time of writing) and the migration plan when an IETF/Noise WG
  standard lands.
- Frozen byte-exact KAT (`hybrid::tests::frozen_hybrid_handshake_kat`)
  pinning our wire stream — msg1, msg2, and both transport-key probe
  ciphertexts — so any future refactor that quietly changes the
  construction breaks the test immediately rather than silently breaking
  interop with our own past releases.
