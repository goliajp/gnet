# Changelog

All notable changes to `mesh-rand` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `meshcli` into a standalone zero-dependency stone:
  cryptographically-secure OS randomness read from `/dev/urandom` via `std`
  only (no `unsafe`, no crates.io deps). `try_fill` / `fill` / `random_32` /
  `random_u32` cover Noise ephemeral + static key generation and transport
  session indices. Unix targets (Linux, macOS, the BSDs); Windows (via a CSP
  syscall) is a future addition.
- README, dual LICENSE, crates.io metadata. A lean I/O utility stone, so no
  bench/BUDGETS (matches the other utility stones).
