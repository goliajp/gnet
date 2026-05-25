# Changelog

All notable changes to `mesh-wire` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `meshcli`'s internal `wire` module into a standalone
  zero-dependency stone: datagram type tags (`Kind`), `frame` / `parse`, the
  allocation-free transport-header field codecs (`put_index` / `index` /
  `put_counter` / `counter`), and the compact `SocketAddr` codec
  (`encode_addr` / `decode_addr`).
- Hand-rolled `std::time` framing benchmark (`benches/framing.rs`) and a
  `tests/perf_gate.rs` regression gate for the per-packet transport-header path.
- `BUDGETS.md` baseline, README, dual LICENSE, crates.io metadata. Zero
  dependencies; the transport path is allocation-free.
- `Kind::RelayData` (0x08): the relay-fallback datagram tag (CP3). Tags traffic
  forwarded through a mutually reachable relay when two peers cannot hole-punch
  a direct path; pairs with the `mesh-relay` `src ‖ dst ‖ inner` envelope. The
  relay routes by `dst` and never decrypts the inner bytes.
- `encode_addr_into` + `ADDR_MAX`: an allocation-free `SocketAddr` encoder into a
  caller-supplied buffer; the owned `encode_addr` now wraps it. Lets the
  endpoint-probe reply path build its datagram on the stack.
