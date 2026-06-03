# Changelog

All notable user-visible / operator-visible / wire-affecting changes to
the `gnet` daemon, the `gnet-discover` coordinator, and the
`gnet-relay-server` relay land here. Library-crate internal changes
(`gnet-crypto`, `gnet-noise`, etc.) appear only when they cross the wire
or change an operator-facing invariant.

Format: [Keep a Changelog](https://keepachangelog.com/).

## Versioning

`gnet` follows **semantic versioning starting at 1.0.0** — the
workspace version, the git tag line, and the wire-compat contract are
all unified at `1.0.0` going forward. Concretely:

- **patch (1.0.x):** bug-fixes, doc, CI; no wire change, no surface
  change.
- **minor (1.x.0):** new features, additive CLI / event-log /
  metrics surface; **wire-compat within the same major** (a 1.x daemon
  always interoperates with a 1.y daemon on the mesh).
- **major (x.0.0):** wire-break; coordinated upgrade across the fleet
  required.

Pre-1.0 history (`gnet-v0.5` through `gnet-v0.20`) shipped under a
different naming scheme — the workspace carried `2.0.0-alpha.2` as a
carryover from the pre-split `goliajp/portal` monorepo, and shipping
cuts were tagged `gnet-v0.N`. Those tags remain in git as historical
artifacts; 1.0.0 is the canonical line from here. (Intermediate
administrative tags `gnet-v0.21` through `gnet-v0.24`, which were
created during the v1.0 release-cut and never shipped as separate
public releases, have been removed — their content is rolled into the
1.0.0 release entry below.)

---

## [1.0.0] — 2026-06-03

The first public release. The repo has been on GitHub since
`2026-05-28`; 1.0.0 is the line where the workspace is feature-complete
for self-use, quality-gated against published cryptographic vectors,
and documented well enough to hold up to outside scrutiny.

### Headline

- A **zero-dependency, post-quantum-ready encrypted overlay** in pure
  Rust, WireGuard-class. Nine library crates ("the stones") carry **no
  `crates.io` dependencies whatsoever**, every primitive hand-rolled
  and KAT-validated.
- Three daemon binaries (`gnet`, `gnet-discover`, `gnet-relay-server`)
  cover data plane + control plane + relay.
- Post-quantum hybrid Noise_IK + ML-KEM-768 handshake.
- Working internal fleet (macOS arm64 + Linux x86_64 + AWS Graviton
  aarch64) operating green.

### Added — observability (operator surface)

- **`gnet status` fused view** — coordinator block now layers per-row
  live session/path/last-handshake state by alias. A `runtime` block
  above shows reflexive endpoint, NAT verdict, per-relay health age.
- **Admin unix-socket IPC** on the daemon
  (`/var/run/gnet/admin.sock` on Linux,
  `/usr/local/var/run/gnet/admin.sock` on macOS) — line-oriented
  `event=`-style snapshot. Zero new deps.
- **`gnet metrics`** — Prometheus text exporter from the admin
  snapshot: counters
  (`handshake_success_total`, `handshake_fail_total`,
  `relay_register_sent_total`, `peer_relay_fallback_total`) and
  gauges (`peers_total`, `peer_session_{idle,initiating,established}`,
  `peer_via_relay`, `relay_health_age_ms{endpoint=…}`). Designed for
  node_exporter's textfile collector.
- **`gnet doctor`** — pre-flight diagnostic with PASS/WARN/FAIL
  per check + green/red verdict + non-zero exit on FAIL. Checks conf
  parse, private-key derive, coordinator reachability + pubkey
  recognition, admin socket, /etc/hosts splice, service unit state.

### Added — quality gates frozen

- [`SECURITY.md`](SECURITY.md) — disclosure policy
  (`security@golia.jp`), threat model, SLA (3-business-day ack /
  10-business-day triage), primitive inventory.
- [`crates/gnet-crypto/KAT.md`](crates/gnet-crypto/KAT.md) — frozen
  RFC/NIST vector inventory: ChaCha20 + Poly1305 (RFC 8439), X25519
  (RFC 7748), BLAKE2s (RFC 7693), SHA-3 + SHAKE (FIPS 202), ML-KEM-768
  (FIPS 203 ACVP). Documented gaps (HKDF-BLAKE2s, Noise IK end-to-end,
  hybrid Noise+ML-KEM) with justification.
- [`crates/gnet-crypto/CT-REVIEW.md`](crates/gnet-crypto/CT-REVIEW.md)
  — constant-time audit of every secret-touching hot path with the
  mechanism that keeps it CT.
- [`docs/fuzzing.md`](docs/fuzzing.md) — `cargo-fuzz` harnesses for
  the 4 untrusted-input parsers: `gnet-wire` (`wire_parse`),
  `gnet-config` (`config_parse`), `gnet-relay` (`relay_decode`),
  `gnet-noise` (`noise_read_message_1`). 17M+ exec/10s on the
  byte-level parsers, 0 panics across all four.

### Added — repo presentation

- [`CONTRIBUTING.md`](CONTRIBUTING.md), `.github/PULL_REQUEST_TEMPLATE.md`
  (enforces Wire/CT/KAT verdict), `.github/ISSUE_TEMPLATE/*`.
- Deploy docs: [Linux + systemd overlay daemon](docs/deploy/linux-systemd.md),
  [coordinator](docs/deploy/coordinator.md),
  [relay-server](docs/deploy/relay-server.md),
  [macOS + launchd](docs/deploy/macos-launchd.md). First systemd unit
  for the coordinator
  ([`crates/gnet-discover/deploy/gnet-discover.service`](crates/gnet-discover/deploy/gnet-discover.service)).
- **GitHub Actions CI** — fmt, clippy, workspace tests, rustdoc,
  perf_gate (release, non-blocking), examples smoke-test, publish
  dry-run on leaf crates. Green on develop.
- **Toolchain policy: always latest stable.** `rust-toolchain.toml`
  keeps `channel = "stable"`; CI uses `dtolnay/rust-toolchain@stable`.
  No version pinning.

### Added — Track A polish (carried in from pre-1.0 shipping cuts)

- Relay health probing + failover via keepalive echo.
- Discovery peer-leave / reconcile (vanished coordinator-sourced peers
  removed; static-conf peers stay pinned).
- Coordinator warm-standby with read-only fence — a standby with
  `GNET_DISCOVER_PRIMARY` set serves reads but rejects admin writes.
- Coordinator state export + backup pull-sync via atomic tmp+rename.
- Node-side multi-coordinator failover.
- Relay-server registration keepalive for idle nodes.

### Fixed (notable)

- **ML-KEM Decaps FO mask via `wrapping_sub` instead of `if`-else**
  — the `if ok { 0 } else { 0xff }` form could lower to a conditional
  jump, leaking the FO check outcome via timing. Wrap-arithmetic form
  compiles to unconditional `cmp + sete + sub` on every backend.
  Wire-format unchanged; ACVP vectors still pass.
- `hosts.rs` `splice_atomic` falls back to a direct
  `truncate + write_all` when a strict systemd sandbox blocks tmp-file
  creation in the target's parent.
- Systemd unit `gnet@.service` gains `RuntimeDirectory=gnet` and
  `AF_UNIX` in `RestrictAddressFamilies` so the admin socket can bind
  without punching `ProtectSystem=strict`.
- `Peer::last_established_at` stamped at both production Established
  transitions in the handshake; surfaces as `last_established_age_s`
  in the admin snapshot.
- `gnet status` `pgrep` matches the daemon's cmdline `gnet up`, not
  the bare process name `gnet`.

### Changed — semver unification

- Workspace version unified at **1.0.0** (from the carryover
  `2.0.0-alpha.2` inherited from the pre-split `goliajp/portal`
  monorepo).
- The five intermediate administrative tags created during the v1.0
  release-cut (`gnet-v0.21`, `gnet-v0.22`, `gnet-v0.23`, `gnet-v0.24`,
  `gnet-v1.0`) have been removed in favour of the single semver tag.
- **Tag naming dropped the `gnet-` prefix** at the same time. The
  daemon tag line is now bare semver (`v1.0.0`, `v1.0.1`, `v1.1.0`,
  `v2.0.0`, …), matching the kevy-style release URL shape. Pre-existing
  tags `gnet-v0.5` through `gnet-v0.20` stay as historical artifacts
  (they predate the unification).

### Out-of-scope deferrals (called out so they don't surprise readers)

- **The control-plane SaaS** (Tailscale-style web admin + account
  model + OAuth at `gnet.golia.jp`) is **v1.1**, a separate project
  built on Rust + axum + Postgres 18 + Valkey 9 + React 19. See
  [ROADMAP.md](ROADMAP.md) "Post-1.0 plan".
- **ACL / policy rules, subnet routes, exit nodes, multi-org, mobile
  clients** — all v2.x; ACL would be a wire+coordinator change far
  beyond a UI addition.
- **Publishing the library crates to crates.io** — decoupled,
  post-1.0. Topology already passes per-crate dry-runs
  ([`crates/PUBLISH.md`](crates/PUBLISH.md)); scheduling is
  independent of the daemon tag line.

---

# Pre-1.0 history

These are the shipping cuts that pre-date 1.0.0. They stayed under
the original `gnet-v0.N` naming because they predate the semver
unification; the bullets below reflect what landed in each cut.

## [gnet-v0.20] — Track A finish

- Relay health probing + failover via keepalive echo.
- Discovery peer-leave / reconcile.

## [gnet-v0.19] — A6 warm-standby read-only fence

A standby coordinator (one with `GNET_DISCOVER_PRIMARY` set) is now
read-only: serves `/peers` and `/healthz` from its mirrored state but
rejects `/admin/*` writes — failover is a config edit + restart on
the standby, not a silent fork of the device table.

## [gnet-v0.18] — A6 core + multi-coord + relay registration keepalive

- Coordinator state export + backup pull-sync; standby coordinator
  mirrors the primary's `state.json` on an interval.
- Node-side multi-coordinator failover (discovery loop walks the
  configured coordinator list in preference order).
- Relay-server registration keepalive: idle nodes stay reachable
  through a relay via self-addressed `RelayData` envelopes.

## [gnet-v0.17] — A5: relay-server in the active path

`gnet-relay-server` standalone deploy wired into the live mesh; picked
up via the coordinator's `GNET_DISCOVER_RELAYS` env var and
distributed to nodes through `/peers`. Daemons fall back to the relay
path automatically when DCUtR can't punch.

## [gnet-v0.16] — A3: daemon /etc/hosts auto-splice

Discovery loop re-splices the gnet-managed block in `/etc/hosts` on
every peer-set change.

## [gnet-v0.15] — A4: structured event log

Every operational outcome the daemon used to log as free-form text
now has a stable `event=<name>` tag plus `key=value` fields.

## [gnet-v0.14] — A2: daemon contrib

Systemd template `gnet@.service` and macOS launchd plist
`com.gnet.gnet.plist` shipped with the repo.

## [gnet-v0.13] — A1: cross-NAT hit-rate measurement

`docs/measurements/v0.13/` netns harness measures DCUtR punch success
across symmetric/asymmetric NAT topologies.

## [gnet-v0.12] — DCUtR fan-out via CandidateSet

Symmetric-NAT port-prediction candidates from `gnet-punch` plumbed into
the daemon's dial fan-out path.

## [gnet-v0.11] — gnet-relay-server standalone + symmetric-NAT port prediction

- Standalone `gnet-relay-server` daemon binary.
- Symmetric-NAT port-prediction candidates in `gnet-punch`.
- `gnet-crypto` ML-KEM AVX2 16-way `ntt_mul` on x86_64.

## [gnet-v0.10] — x86_64 AVX2 pre-flight

`gnet-bench-compare` measured ceiling on x86_64 AVX2.

## [gnet-v0.9] — NEON intrinsic schedule

`gnet-crypto` AEAD closed the gap to RustCrypto on Apple Silicon NEON.

## [gnet-v0.8] — AVX2 Keccak + NTT

`gnet-crypto` AVX2 4-way Keccak-f[1600] + 16-way NTT/invNTT for
x86_64.

## [gnet-v0.5] — first fleet-candidate daemon

The v0.5 daemon (`gnet up <config>`) became operationally usable:
DCUtR path selection, relay fallback on punch failure, expire stuck
`PunchState::Connecting`, periodic direct-path upgrade scheduler.
Sufficient to run an internal fleet from.

---

[1.0.0]: https://github.com/goliajp/gnet/releases/tag/v1.0.0
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
