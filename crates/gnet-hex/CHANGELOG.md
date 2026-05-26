# Changelog

All notable changes to `gnet-hex` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `gnet`'s internal `hex` module into a standalone
  zero-dependency stone: `encode`, `decode`, `decode_32`. Lowercase output,
  even-length whitespace-trimmed input.
- Randomized roundtrip property test via the sibling `gnet-rand`; dual LICENSE +
  crates.io metadata. Cold-path utility, so no bench/BUDGETS (matches the other
  utility stones).
