# Changelog

All notable user-visible / operator-visible / wire-affecting changes to
the `gnet` daemon, the `gnet-discover` coordinator, and the
`gnet-relay-server` relay land here. Library-crate internal changes
(`gnet-crypto`, `gnet-noise`, etc.) appear only when they cross the wire
or change an operator-facing invariant.

Format: this file follows [Keep a Changelog](https://keepachangelog.com/);
the project follows the version policy in [ROADMAP.md](ROADMAP.md) (the
tag line is `gnet-v*`; minor bumps don't break wire compat within the
same major).

---

## [gnet-v1.0] — 2026-06-03

The first public release. The repo has been on GitHub since
`2026-05-28`; v1.0 is the line where the workspace is feature-complete
for self-use, quality-gated against published cryptographic vectors, and
documented well enough to hold up to outside scrutiny.

### What this is

- A zero-dependency, post-quantum-ready encrypted overlay in pure Rust,
  WireGuard-class. Nine library crates ("the stones") carry **no
  `crates.io` dependencies whatsoever**, every primitive hand-rolled and
  KAT-validated; three daemon binaries (`gnet`, `gnet-discover`,
  `gnet-relay-server`) cautiously layer the few deps the binary side
  needs.
- A working internal fleet (macOS arm64 + Linux x86_64 + AWS Graviton
  aarch64) has been on the v0.21+ stack since 2026-06-02; the system
  has been observable and self-operatable since then.

### v1.0 adds nothing over v0.24 — it's the release tag

This release is `git tag gnet-v1.0` + this CHANGELOG + the green CI
state on `develop` (run [#4
26854620641](https://github.com/goliajp/gnet/actions/runs/26854620641)).
No code change, no wire change, no surface change. v0.24 was the last
shipping change; v1.0 is the line.

### Out-of-scope deferrals (called out so they don't surprise)

- **The control-plane SaaS (Tailscale-style web admin + account model +
  OAuth at `gnet.golia.jp`)** is scoped as **v1.1**, a separate project
  built on Rust + axum + Postgres 18 + Valkey 9 + React 19 (see
  ROADMAP.md "Post-1.0 plan").
- **ACL / policy rules, subnet routes, exit nodes, multi-org, mobile
  clients** — all v2.x; ACL specifically would be a wire+coordinator
  change far beyond a UI addition.
- **Publishing the library crates to crates.io** — decoupled, post-1.0.
  Topology already passes per-crate dry-runs (`crates/PUBLISH.md`);
  scheduling is independent of the daemon tag line.

---

## [gnet-v0.24] — 2026-06-03 — Track E: open-source presentation

The repo-as-a-public-project sweep.

### Added

- `CONTRIBUTING.md` — repo layout, dev loop, non-negotiable invariants
  (zero-deps stones, wire compat within minor, KAT+CT review for crypto
  changes), commit style, PR flow.
- `.github/PULL_REQUEST_TEMPLATE.md` enforcing a Wire/CT/KAT verdict
  line on every PR.
- `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md` — security
  bugs routed to `SECURITY.md`; feature requests prompted to self-bucket
  against the roadmap.
- `docs/deploy/coordinator.md` + `crates/gnet-discover/deploy/gnet-discover.service`
  — first systemd unit for the coordinator (DynamicUser +
  StateDirectory + strict sandbox).
- `docs/deploy/relay-server.md` — install, advertise-via-coord, verify,
  hardening, wire-format scope, cloud-egress notes.
- `docs/deploy/macos-launchd.md` — `launchctl bootstrap` flow, plist
  semantics, macOS-vs-Linux path differences for conf and admin socket.
- README updated to reflect v0.21–v0.24 landings with an "Operating"
  CLI table.

### Changed

- **Toolchain policy locked in as "always latest stable"** —
  `rust-toolchain.toml` keeps `channel = "stable"`, CI uses
  `dtolnay/rust-toolchain@stable`. No version pinning.
- One-shot codebase reflow against current rustfmt (rustc 1.96.0 /
  rustfmt 1.9.0) — 49 files, pure whitespace, no semantic change.
- GitHub Actions CI is registered + green: fmt, clippy, workspace
  tests, rustdoc, perf_gate (release, non-blocking), examples,
  publish dry-run. Auto-registration of `ci.yml` had been silently
  failing since the 2026-05-28 split; adding `workflow_dispatch:`
  trigger nudged it. (Known oddity: `on: push` events not auto-firing
  CI as of 1.0 — only `workflow_dispatch` works; suspected repo
  setting around first-time-contributor approval.)

### Fixed

- Two `clippy::needless_range_loop` warnings on x86_64 Linux in
  AVX2 intrinsic loops (`mlkem/ntt/avx2.rs`, `sha3/avx2_x4.rs`) —
  index-driven loops are intentional there; added `#[allow]` with
  rationale.
- `gnet-bench-compare`'s `perf_gate` tests excluded from the debug
  `cargo test --workspace` step; they only make sense in release.
- `keccak_f_baseline_microbench` marked `#[ignore]` — it's a soft
  ceiling reference, not a regression gate; was flaking on shared CI.

---

## [gnet-v0.23] — 2026-06-03 — Track B: quality gate

Public-scrutiny credibility.

### Added

- `SECURITY.md` — disclosure policy (`security@golia.jp`), SLA
  (3-business-day ack / 10-business-day triage), threat model, primitive
  inventory.
- `crates/gnet-crypto/KAT.md` — frozen RFC/NIST vector inventory:
  ChaCha20 + Poly1305 (RFC 8439), X25519 (RFC 7748), BLAKE2s
  (RFC 7693), SHA-3 + SHAKE (NIST FIPS 202), ML-KEM-768 (NIST FIPS 203
  ACVP). Documented gaps (HKDF-BLAKE2s, Noise IK end-to-end, hybrid
  Noise+ML-KEM) with their justification.
- `crates/gnet-crypto/CT-REVIEW.md` — constant-time audit of every
  secret-touching hot path with the mechanism that keeps it CT and the
  assumptions that mechanism rests on.
- `cargo-fuzz` harnesses for the 4 untrusted-input parsers: `gnet-wire`
  (`wire_parse`), `gnet-config` (`config_parse`), `gnet-relay`
  (`relay_decode`), `gnet-noise` (`noise_read_message_1`).
  `docs/fuzzing.md` documents the run protocol. Smoke results: 17M+
  exec/10s on the byte-level parsers, 0 panics.

### Fixed

- **ML-KEM Decaps FO mask via `wrapping_sub` instead of `if`-else**
  (commit `e73809d`). The `if ok { 0 } else { 0xff }` form was free to
  lower to a conditional jump, which would have leaked the FO check
  outcome via timing — exactly what the implicit-rejection key is
  supposed to hide. The wrap-arithmetic form compiles to unconditional
  `cmp + sete + sub` on every backend gnet targets. Wire-format
  unchanged; ACVP vectors still pass.

---

## [gnet-v0.22] — 2026-06-03 — Track F: small polish

### Added

- `gnet doctor [--conf PATH]` — pre-flight green/red verdict
  subcommand. Checks conf parse, private-key derive, coordinator
  reachability + pubkey recognition (GET /peers as a non-mutating
  probe), admin socket, /etc/hosts splice, service unit. Exits
  non-zero on FAIL.

---

## [gnet-v0.21] — 2026-06-02 — Track C: observability

The operator-visibility milestone — `gnet status` stops being conf +
coordinator-only and becomes a live picture.

### Added

- **Admin unix-socket IPC** on the daemon
  (`/var/run/gnet/admin.sock` on Linux,
  `/usr/local/var/run/gnet/admin.sock` on macOS). Line-oriented
  `event=`-style snapshot with per-peer session phase, current
  reflexive endpoint, NAT verdict, and per-relay health age. Zero new
  deps.
- **`gnet status` fused view** — the coordinator block now layers live
  session/path/last-handshake state per row by alias. A new `runtime`
  block above `coordinator` shows reflexive / `self_is_nat` / per-relay
  health.
- **`gnet metrics` subcommand** — reads the admin snapshot and emits
  Prometheus text (counters for handshake_success / handshake_fail /
  relay_register_sent / peer_relay_fallback; gauges for
  peer_session_{idle,initiating,established} / peer_via_relay /
  relay_health_age_ms{endpoint=…}). Designed to feed node_exporter's
  textfile collector.

### Fixed

- `Peer::last_established_at` is stamped at both production Established
  transitions in the handshake.
- `hosts.rs` `splice_atomic` falls back to a direct `truncate+write_all`
  when the sandbox blocks tmp-file creation (systemd `ProtectSystem=strict`
  with only `/etc/hosts` in `ReadWritePaths`). Worst-case race exposes a
  briefly-truncated file; resolver then falls back to DNS.
- `gnet status` `pgrep` matches the daemon's cmdline `gnet up`, not the
  bare process name `gnet` — previously the daemon row showed two pids
  whenever the status invocation also matched.

### Changed

- Systemd unit `gnet@.service` gains `RuntimeDirectory=gnet` (so
  `/run/gnet/` materialises for the admin socket without punching
  `ProtectSystem=strict`) and `AF_UNIX` in `RestrictAddressFamilies`.

---

## [gnet-v0.20] — Track A finish — daemon feature-complete

### Added

- Relay health probing + failover via keepalive echo. The daemon's
  relay-register loop now exchanges health pongs; `relay_data_endpoint`
  prefers a relay whose pong is within `RELAY_HEALTH_WINDOW`, routing
  around a dead relay automatically.
- Discovery peer-leave / reconcile. Coordinator-sourced peers that
  vanish from a successful `/peers` poll are now removed (static-conf
  peers stay pinned).

---

## [gnet-v0.19] — A6: warm-standby read-only fence

A standby coordinator (one with `GNET_DISCOVER_PRIMARY` set) is now
**read-only**: it serves `/peers` and `/healthz` from its mirrored
state but rejects `/admin/*` writes. A failover is a config edit +
restart on the standby, not a silent fork of the device table.

---

## [gnet-v0.18] — A6 core + node-side multi-coordinator failover + relay-server registration keepalive

### Added

- Coordinator state export + backup pull-sync; standby coordinator now
  mirrors the primary's `state.json` on an interval and persists each
  pull via the atomic tmp+rename so the on-disk snapshot is always a
  valid restore point.
- Node-side multi-coordinator failover: the discovery loop walks the
  configured coordinator list in preference order and survives any one
  being down.
- Relay-server registration keepalive: idle nodes stay reachable
  through a relay by sending self-addressed `RelayData` envelopes on a
  fixed cadence (so the relay's peer table doesn't age them out).

---

## [gnet-v0.17] — A5: relay-server in the active path

`gnet-relay-server` standalone deploy is now wired into the live mesh
— picked up via the coordinator's `GNET_DISCOVER_RELAYS` env var and
distributed to nodes through `/peers`. Daemons fall back to the relay
path automatically when DCUtR can't punch.

---

## [gnet-v0.16] — A3: daemon /etc/hosts auto-splice

The daemon's discovery loop re-splices the gnet-managed block in
`/etc/hosts` on every peer-set change — so `ssh gnet-<alias>` keeps
working across joins, leaves, and key rotations without a re-join.

---

## [gnet-v0.15] — A4: structured event log

Every operational outcome the daemon used to log as free-form text now
has a stable `event=<name>` tag plus `key=value` fields. Grep-friendly
without a JSON parser.

---

## [gnet-v0.14] — A2: daemon contrib

Systemd template `gnet@.service` and macOS launchd plist
`com.gnet.gnet.plist` ship with the repo; per-deploy install scripts
are documented in unit-file headers.

---

## [gnet-v0.13] — A1: cross-NAT hit-rate measurement

`docs/measurements/v0.13/` netns harness measures DCUtR punch
success across symmetric/asymmetric NAT topologies. Establishes the
baseline that v0.17 relay fallback is measured against.

---

## [gnet-v0.12] — DCUtR fan-out via CandidateSet

Symmetric-NAT port-prediction candidates from `gnet-punch` plumbed
into the daemon's dial fan-out path.

---

## [gnet-v0.11] — gnet-relay-server standalone + symmetric-NAT port prediction

### Added

- Standalone `gnet-relay-server` daemon binary — minimal, sandboxed,
  forwards `Kind::RelayData` envelopes by destination static key,
  never decrypts.
- Symmetric-NAT port-prediction candidates in `gnet-punch`.

### Perf

- `gnet-crypto` ML-KEM AVX2 16-way `ntt_mul` on x86_64.

---

## [gnet-v0.10] — x86_64 AVX2 pre-flight

`gnet-bench-compare` measured ceiling on x86_64 AVX2. Establishes
the perf-gate caps used by CI.

---

## [gnet-v0.9] — NEON intrinsic schedule

`gnet-crypto` AEAD closed the gap to the RustCrypto baseline on
Apple Silicon NEON.

---

## [gnet-v0.8] — AVX2 Keccak + NTT

`gnet-crypto` AVX2 4-way `Keccak-f[1600]` + 16-way NTT/invNTT for
x86_64.

---

## [gnet-v0.5] — daemon path selection — first fleet candidate

The v0.5 daemon (`gnet up <config>`) became operationally usable:
DCUtR path selection, relay fallback on punch failure, expire stuck
`PunchState::Connecting`, periodic direct-path upgrade scheduler.
Sufficient to run an internal fleet from.

---

[gnet-v1.0]: https://github.com/goliajp/gnet/releases/tag/gnet-v1.0
[gnet-v0.24]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.24
[gnet-v0.23]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.23
[gnet-v0.22]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.22
[gnet-v0.21]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.21
[gnet-v0.20]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.20
[gnet-v0.19]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.19
[gnet-v0.18]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.18
[gnet-v0.17]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.17
[gnet-v0.16]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.16
[gnet-v0.15]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.15
[gnet-v0.14]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.14
[gnet-v0.13]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.13
[gnet-v0.12]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.12
[gnet-v0.11]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.11-s3
[gnet-v0.10]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.10
[gnet-v0.9]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.9
[gnet-v0.8]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.8
[gnet-v0.5]: https://github.com/goliajp/gnet/releases/tag/gnet-v0.5
