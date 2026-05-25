# Changelog

All notable changes to `gnet-config` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `gnetcli`'s internal `config` module into a standalone
  zero-dependency stone: `parse`, `Config`, `PeerConfig`. Parses the
  WireGuard-style text config (private / address / listen / keepalive + a peer
  table). Depends only on the sibling stones `gnet-hex` (key codec) and
  `gnet-crypto` (the `EK_LEN` constant).
- Randomized config-roundtrip property test via the sibling `gnet-rand`; dual
  LICENSE + crates.io metadata. Cold-path utility, so no bench/BUDGETS (matches
  the other utility stones).
