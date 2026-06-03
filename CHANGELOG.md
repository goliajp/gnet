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

## [Unreleased] — 1.1.0 (in progress on `develop`)

v1.1 is the **control-plane release**. The data plane is wire-stable
(v1.0 daemons interoperate unchanged on a v1.1 fleet), but the surface
around it grows substantially: a PG-backed dispatcher with an admin
API, a SaaS-side console (`gnet.golia.jp`) that federates to user
dispatchers, a lite admin surface on the relay, a v1.2-facing
localhost admin endpoint on the daemon, an embedded SPA in three of
the binaries, and a self-host `docker compose` bundle.

The work is tracked under plan §17 in `docs/v1.1-plan.md`; everything
in this entry has landed on `develop`.

### Architectural invariants (unchanged from v1.0)

- **Daemon zero-deps.** `cargo tree -p gnet` resolves to 10 workspace
  crates and zero `crates.io` dependencies — verified across every
  §17 slice. The control-plane crates (`gnet-discover`,
  `gnet-relay-server`, `gnet-console`) carry their own dep trees,
  walled off from the daemon's.
- **v1.0 wire untouched.** `/peers`, `/endpoint-report`, `/join` on
  the dispatcher and the daemon's UDP wire are bit-identical to
  v1.0; a v1.0 daemon talking to a v1.1 dispatcher does not see the
  new admin surface.
- **All v1.1 features opt-in via env.** A dispatcher binary with no
  `GNET_DISCOVER_DATABASE_URL` runs as a pure v1.0 coord; a relay
  with no `GNET_RELAY_ADMIN_BIND` exposes no admin surface; a daemon
  with no `GNET_LOCAL_ADMIN_ENABLE` runs unchanged.

### Added — dispatcher (`gnet-discover`)

- **v1.1 PG schema + state.json importer.** `--import-state` reads
  the legacy `state.json` and round-trips it into PG so an in-place
  v1.0 → v1.1 upgrade preserves device tokens. Schema lives in a new
  `gnet-discover-schema` crate; migrations run automatically on
  admin-server startup (§17.1).
- **Admin API skeleton + local auth.** Cookie session (HttpOnly
  `gnet_sess`, opaque 32-byte bearer hashed to SHA3-256 in Valkey)
  + double-submit CSRF (`gnet_csrf` cookie ↔ `X-Csrf-Token` header)
  + Argon2id passwords. Setup token bootstraps the first
  `owner`-role admin account (§17.2).
- **Daemon push channel.** Daemons periodically POST an admin
  snapshot to `<admin_endpoint>/api/internal/snapshot`
  (bearer-authed by their existing `device_token`); dispatcher
  stores the JSONB blob in `device_snapshots` and surfaces it in
  the SPA (§17.4).
- **Device rename write path.** `PUT /api/devices/{id}/alias`
  validates shape (3..32 chars `[a-z0-9_-]`), enforces uniqueness
  per-network, and writes an `audit_log` row in the same
  transaction. 400/404/409/403 map cleanly (§17.7).
- **Federation receiver.** `POST /api/federation/register` accepts
  a console-issued federation token + console origin; dispatcher
  stores `(SHA3-256(token), origin)` in `federation_trust` and
  thereafter accepts that bearer as an admin identity on the
  proxy-routed API surface (§17.6).
- **Defensive headers + brute-force throttle.** Every response
  carries `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: same-origin`; HSTS added when
  `GNET_DISCOVER_SECURE_COOKIES=1`. Login throttle: per-tenant +
  per-username Valkey counter, 5 attempts / 60s → 429 +
  `Retry-After` (§17.12).

### Added — console (`gnet-console`, gnet.golia.jp)

- **New binary + crate.** Multi-tenant SaaS console: users sign in,
  see their networks (own dispatcher endpoints federated by token),
  and operate them through a transparent proxy surface
  (`/api/networks/:id/proxy/*` → user's dispatcher) (§17.5a).
- **Email + password auth + OAuth.** Argon2id passwords (m=64 MiB,
  t=3, p=4). OAuth providers: Google (§17.5b), GitHub (§17.5c),
  Apple Sign-In with ES256 client_secret JWT + JWKS cache (§17.5d).
- **Federation token issuance.** Deterministic per-user-per-network
  token derived from a server-side master secret + user UUID +
  label + endpoint; the dispatcher receiver stores only its hash,
  so a token leak from one console doesn't compromise others
  (§17.6).
- **Same defensive headers + login rate-limit** as the dispatcher,
  with cookie `Secure` defaulting **on** (SaaS is HTTPS-only) —
  `GNET_CONSOLE_SECURE_COOKIES=0` opts out for dev (§17.12).

### Added — relay (`gnet-relay-server`)

- **Lite admin HTTP surface.** Opt-in via `GNET_RELAY_ADMIN_BIND` +
  `GNET_RELAY_ADMIN_TOKEN`. Endpoints: `GET /api/host-role` (open),
  `GET /api/peers` (bearer), `GET /api/traffic` (bearer). The
  forwarder stays single-threaded; the admin server runs on a
  dedicated OS thread + current-thread Tokio runtime, sharing the
  live peer table via `Arc<RwLock<HashMap>>` and the cumulative
  counters via `AtomicU64`. Daemon dep tree unaffected (§17.8).

### Added — daemon (`gnet`)

- **Local HTTP admin surface (wire contract).** Opt-in via
  `GNET_LOCAL_ADMIN_ENABLE=1`. Hand-rolled HTTP/1.1 parser (the
  daemon zero-deps invariant rules out `httparse`/axum), bearer
  auth against `/var/db/gnet/admin_token` (Linux) or
  `/Library/Application Support/gnet/admin_token` (macOS), mode
  must be exactly `0o400`. Routes: `/local/{status,alias,quit,
  restart,join,upgrade}`. **`/local/status` is fully implemented**
  (JSON snapshot of the live Node state); the five write endpoints
  return `501 Not Implemented` with a structured
  `{"not_implemented":..., "ships_in":"v1.2"}` body — the v1.2
  macOS native-app consumer (plan §3.5) fills them in against this
  stable wire. (§17.9)

### Added — SPA + frontend

- **`console/` React 19 + Vite 7 + Tailwind 4 SPA.** Single
  codebase, role-aware: hits `GET /api/host-role` at boot and swaps
  the visible tabs accordingly (dispatcher → Devices / Network /
  Relays / Audit / Settings; relay → Peers / Traffic / Settings;
  console → Networks / per-network proxy / Account / Audit).
- **Embedded into three binaries** via `include_dir!` (plan §3.4):
  the SPA bundle at `console/dist/` is baked into `gnet-discover`,
  `gnet-relay-server`, and `gnet-console` at compile time;
  `build.rs` in each consuming crate writes a stub `index.html`
  when the SPA hasn't been built yet, so `cargo build` works on a
  fresh clone without a Bun toolchain (§17.10a).
- **Inline rename UX on the dispatcher's SPA**, wired to the new
  `PUT /api/devices/{id}/alias` write path (§17.7).

### Added — deployment

- **Self-host docker-compose bundle.** New `self-host/` directory
  ships a multi-stage `Dockerfile` (bun → rust → three minimal
  runtime images), a `docker-compose.yml` with `db` (postgres:18)
  + `kv` (valkey:9) + `dispatcher` + `relay`, `.env.example` with
  required-var assertions, and a `README.md` walking the operator
  through a 5-step init. Mode B (self-host, no SaaS dep) is fully
  brought up by `cp .env.example .env && docker compose up -d`
  (§17.10b).
- **SaaS deploy spec bundle.** New `deploy/saas/` directory holds
  the devops.golia.jp API bodies (`project.json`, `services.json`,
  `caddy-site.json`, `dns-apex.json`, `dns-wildcard.json`), a
  hardened systemd unit, a runtime `.env.local.example`, and a
  6-step register README. The agent does not invoke the devops
  API; the operator pastes these with their own `DEVOPS_API_KEY`
  when the internal fleet has dogfooded long enough (§17.11).

### Added — federation revocation (plan §6.3, §15)

Federation can now be revoked from either side; the two paths are
independent and either alone is sufficient to break the trust.

- **Dispatcher side (operator):** `DELETE /api/federation/{trust_id}`
  sets `federation_trust.revoked_at = now()` + writes an
  `action='federation.revoke'` audit row. The existing
  `auth::require_login` federation-bearer branch already filters
  revoked rows, so the next request bearing the revoked token gets
  the canonical 401 without a separate code path.
- **Console side (user):** `DELETE /api/networks/{id}` soft-deletes a
  `user_networks` row (`removed_at` column added by migration
  `0004_user_networks_removed_at.sql`). The proxy route + the
  network list both filter `removed_at IS NULL` so a removed
  network drops out of the user's view and out of the federation
  forwarder before any token re-derivation happens. UNIQUE
  `(user_id, network_label)` relaxes to a partial index so the
  user can re-register a label they previously removed (the
  derivation is deterministic — a re-register wins back the same
  bearer).

### Added — CI

- **Self-host smoke** (`.github/workflows/self-host-smoke.yml`).
  PRs touching the self-host bundle, the control-plane crates, or
  the SPA bring up `docker compose up -d --build --wait` from
  `self-host/`, then verify with `jq -e`: dispatcher / relay
  `/api/host-role` shape, relay `/api/peers` 401 without bearer +
  empty list with bearer, `/api/traffic` shape. Compose's `--wait`
  blocks on the healthchecks in `docker-compose.yml`, so a service
  that fails to come healthy trips the job before curl runs. Logs
  uploaded as an artefact on failure. (Plan §13, §15.)
- **Upgrade smoke** (`.github/workflows/upgrade-smoke.yml`). PRs
  touching the importer / schema boot a clean `postgres:18-alpine`,
  copy `tests/fixtures/v1_0_state.json` (two devices, one
  env-supplied relay), run `gnet-discover --import-state`, then
  `psql`-assert: `networks.name` matches the env override,
  `count(devices) == 2`, alias list, `count(relays) == 1`, source
  file renamed to `*.imported`. (Plan §15.)

### Security

- **OWASP ASVS L1 walkthrough.** `SECURITY.md` now carries a per-
  control table (V2 / V3 / V4 / V5 / V7 / V8 / V9 / V11 / V12 / V13
  / V14) with status (met / partially met / N/A / deferred) and the
  source location for each control. Defers to v1.2: Content-
  Security-Policy, explicit per-route body limits, per-IP login
  throttle, CAPTCHA on signup, `audit_log` tamper-evidence.
- **Cookie `Secure` flag** controllable per binary via env. Console
  default on, dispatcher default off (matches the deployment posture
  — SaaS is HTTPS-only; self-host's plain-HTTP default would
  otherwise lock the operator out).
- **Login brute-force throttle.** Per-account Valkey counter on both
  console (email login) and dispatcher (local admin login); 5
  attempts / 60s window, 429 + `Retry-After` on exceed.
- **Daemon admin token file** must be exactly mode `0o400`; broader
  permissions cause the local-admin server to refuse to start.

### Wire / surface

- v1.0 admin event log and `/peers` / `/endpoint-report` /
  `/join` responses are byte-identical to v1.0. A v1.0 daemon and
  a v1.1 daemon coexist on the same mesh without coordination.
- New responses (`GET /api/host-role`, the daemon snapshot push,
  etc.) are additive — v1.0 dispatcher binaries silently 404 on
  them, which is the correct behaviour for a v1.0 deployment.

---

## [1.0.2] — 2026-06-03

Patch release. No wire change. Cosmetic + Prometheus label addition.

### Fixed

- **`gnet status` runtime block** no longer says "no pong yet" on a
  public daemon's relay rows. Public daemons don't send relay-register
  packets at all (`self.self_is_nat == Some(false)` → register
  no-ops), so "no pong yet" was structurally misleading — there's no
  pong because there was never a register. Now displays
  "advertised; we're public — no register sent" in that case.

### Changed

- **`gnet metrics` `gnet_relay_health_age_ms` gauge gains a
  `registered="true|false"` label.** Public daemons emit the gauge with
  `registered="false"` so staleness alerts can filter
  (`gnet_relay_health_age_ms{registered="true"} > 60000`) and not
  false-fire on public nodes whose 0-valued health age is by design.
  Existing endpoint-only queries continue to work (Prometheus label
  selectors are subset-match).

---

## [1.0.1] — 2026-06-03

Patch release. No wire change. Picked up two fleet-operational
findings from the v1.0.0 Tier-4 Docker-onboarding test.

### Fixed

- **`gnet doctor` recognises container env.** `/.dockerenv` or
  `/run/.containerenv` present → service-unit check is a PASS with
  "running inside a container (host service-unit check skipped)",
  not a misleading WARN. A healthy `goliakk/gnet:*` container now
  shows GREEN instead of AMBER.

### Operational (out-of-tree)

- Fleet `gnet-relay-server` processes deployed on `t01` (public) and
  `t02` (public), both bound `:65433`. Coordinator env extended:
  `GNET_DISCOVER_RELAYS=18.179.107.143:65433,52.195.89.111:65433`.
  Coordinator's `gnet-discover` binaries on t01 + t02 rebuilt to a
  version that actually serves the `{peers, relays}` wrapped response
  shape (the pre-v0.17 binaries on disk had been silently returning
  a bare peer array, suppressing the relay advertisement). Fleet
  daemons learn the relays on next `/peers` poll.
- **Operator-side gap surfaced:** AWS Security Groups on the
  coordinator EC2 instances do not currently allow inbound UDP 65433,
  so relay-register packets reach the public IP but get dropped at
  the SG; daemons emit register packets fine
  (`gnet_relay_register_sent_total` ticks) but no echo pong arrives
  (`gnet_relay_health_age_ms{endpoint=…} 0`, "no pong yet").
  Direct/punch paths within the existing fleet are unaffected.
  Fix: open UDP 65433 in the two SGs.

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

[1.0.2]: https://github.com/goliajp/gnet/releases/tag/v1.0.2
[1.0.1]: https://github.com/goliajp/gnet/releases/tag/v1.0.1
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
