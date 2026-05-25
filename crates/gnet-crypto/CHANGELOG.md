# Changelog

All notable changes to `gnet-crypto` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `gnetcli` into a standalone zero-dependency cryptographic
  core, every primitive hand-written in pure Rust and validated against its
  published known-answer vectors: ChaCha20 + Poly1305 + the ChaCha20-Poly1305
  AEAD (RFC 8439), X25519 (RFC 7748), BLAKE2s + keyed MAC (RFC 7693), HKDF
  (RFC 5869), SHA-3 / SHAKE (FIPS 202), and the ML-KEM-768 post-quantum KEM
  (FIPS 203) for the hybrid handshake.
- Hand-rolled `std::time` benchmark (`benches/crypto.rs`), a `tests/perf_gate.rs`
  regression gate, and a `BUDGETS.md` baseline for the hot primitives.
- README, dual LICENSE, crates.io metadata. Zero dependencies; constant-time
  where secrets are involved.
