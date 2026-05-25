# Changelog

All notable changes to `gnet-punch` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `gnetcli`'s `node/punch.rs`: the zero-I/O rendezvous codec
  (`encode_connect` / `decode_connect` / `encode_sync` / `decode_sync`) and the
  `PunchState` machine (`Idle` / `Connecting` / `Syncing` / `Awaiting`) with
  `on_reply` (RTT/2 dial scheduling) and `due_dial`. The Node-coupled wiring
  (relay / dial / `handle_connect` / `handle_sync` / `poll_punch_dials`) stays in
  gnetcli as cement.
- 0-dep beyond `gnet-wire`; hand-rolled std::time bench, `BUDGETS.md`,
  `tests/perf_gate.rs`, randomized codec property test via `gnet-rand`,
  README / dual LICENSE / crates.io metadata.
