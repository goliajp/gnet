# gnet roadmap

> The destination and the version boundary. This document fixes *what
> the next major / minor releases contain* and *what order* the work
> lands in — deliberately without per-step detail. Step-level plans
> live per checkpoint.

## Where we are

- **Tag line:** `v1.0.0`, released 2026-06-03. Workspace version
  unified at `1.0.0` (semver from here; see CHANGELOG.md "Versioning"
  for the carryover history).
- Internal fleet (macOS arm64 + Linux x86_64 + AWS Graviton aarch64)
  running the v1.0.0 stack, observable via `gnet status` / `gnet metrics`
  / structured event log.
- Data plane: zero-deps, post-quantum hybrid Noise_IK + ML-KEM-768,
  KAT-validated against RFC/NIST/ACVP vectors, CT-audited
  (see [CT-REVIEW.md](crates/gnet-crypto/CT-REVIEW.md)),
  fuzz-harnessed (see [fuzzing.md](docs/fuzzing.md)).
- Control plane (`gnet-discover`) + standalone `gnet-relay-server` both
  wired into the active path; coordinator supports warm-standby with a
  read-only fence; relays have health-probed failover.
- CI green on `develop`
  ([latest run](https://github.com/goliajp/gnet/actions/runs/26854620641));
  toolchain policy is **always latest stable** (`rust-toolchain.toml`
  channel = "stable"; CI `dtolnay/rust-toolchain@stable`).

## Versioning

`gnet` follows **semantic versioning starting at 1.0.0**. The workspace
version, the git tag line (`vX.Y.Z` — bare semver, kevy-style; the
historical `gnet-v0.x` prefix is dropped), and the wire-compat contract
are unified. Concretely:

- **patch (1.0.x):** bug-fixes, doc, CI; no wire change, no surface
  change.
- **minor (1.x.0):** new features, additive CLI / event-log / metrics
  surface; **wire-compat within the same major** (a 1.x daemon always
  interoperates with a 1.y daemon on the mesh).
- **major (X.0.0):** wire-break; coordinated upgrade across the fleet
  required.

Major bumps earn a deliberate **observation window** on the internal
fleet before the next major's work starts. Minor / patch cadence has
no such window; checkpoints flow into each other directly.

Pre-1.0 history (`gnet-v0.5` through `gnet-v0.20`) shipped under the
old carryover scheme — see [CHANGELOG.md](CHANGELOG.md) for the full
arc.

## Forward plan

### 1.0.x — patch lane

Bug-fixes, doc, CI hardening. Specifically expected to land here:

- `on: push` CI auto-trigger if a repo-Settings investigation surfaces
  a fix (currently only `workflow_dispatch` fires).
- Fleet-surfaced bugs caught by `journalctl | grep event=` during the
  v1.0 observation window.

### 1.1.0 — SaaS control plane + console at gnet.golia.jp

The Tailscale-style account-and-network surface for `gnet`. Built **in
this repo, not a separate one** (the original roadmap revision called
for a split — reverted because keeping the control plane next to the
daemon makes versioning, fleet rollouts, and the push-channel wire
contract easier to keep aligned).

Layout: new workspace members under `crates/` for the backend
(probably `gnet-console` for the axum app + `gnet-console-schema` for
PG migrations + types) and a sibling `console/` tree at the repo root
for the React SPA (Vite build output bundled into the backend binary
via `include_dir!` at compile time, single-binary deploy in the same
shape as `gnet-discover`).

**Architectural ground rules (non-negotiable):**

- **Separate process, separate deploy.** Even though it lives in this
  repo, the control plane is its own binary on its own host — a
  control-plane outage must not stop existing devices from talking.
  Once a device is registered, day-to-day overlay traffic uses only
  the cached coord roster and direct/relay paths.
- **Authoritative state in Postgres.** The current `state.json`
  becomes a cache / projection; user/account/network/device records
  live in PG.
- **Coordinator stays the fan-in for node telemetry**, but its
  backing store moves from a JSON file to PG. The push channel
  (v1.1-A) writes node snapshots through the coord into PG; the
  console reads from PG.
- **Zero-deps daemon stays zero-deps.** The push channel is one new
  POST in the daemon; no SDK, no proto compiler. The console's heavy
  deps (axum, sqlx, valkey-client, etc.) live behind the new console
  crates and never enter the daemon's dep tree — the CI
  `cargo publish --dry-run` check on the leaf crates guards this.
- **Self-host supported via Docker Compose** (axum + PG + Valkey).
  Hosted at `gnet.golia.jp` is the SaaS default.

**Account model:**

- **User** — auth identity. Has zero or more **OAuthIdentity** rows
  (provider ∈ {google, github, apple}, provider_subject), and
  optionally an email/password credential.
- **Network** (a Tailscale "tailnet"): a logical mesh with its own
  overlay subnet, its own relay servers, its own coord. A user may
  own multiple networks.
- **Device** — a `gnet` daemon. Belongs to exactly one Network.
  Carries its X25519 pubkey, ML-KEM ek, current device_token, last
  reflexive endpoint, current alias, current overlay vIP.
- **Member** (deferred to 1.2.0): a User granted access to another
  User's Network.

**Tech stack:**

- **Backend:** Rust + axum, Postgres 18, Valkey 9 — in this workspace
  under new `crates/gnet-console*` members (kept out of the daemon's
  dep tree so the zero-deps stones stay zero-deps).
- **Frontend:** React 19 + Vite 7 + Tailwind CSS 4 + react-router +
  `@tanstack/react-query` + Jotai (atoms). SPA, CSR.
- **Auth:** OAuth (Google / GitHub / Apple) + email/password.
  Sessions in Valkey, cookie-based.
- **TLS / hosting:** behind Caddy on `gnet.golia.jp`.

**Phase breakdown (each goes hot when its trigger fires):**

| Phase | Content | Trigger |
|---|---|---|
| **1.1-A** | Node → coord push channel. Daemon POSTs admin snapshot + new events to coord every N seconds (or on event-emit, batched). Coord keeps latest snapshot per device + ring buffer. Existing GET /peers poll unchanged. | v1.0 observation window passed |
| **1.1-B** | Account/Network/Device schema in PG18 + axum scaffolding. Baseline app, health check, migrations harness. | 1.1-A push data shape stable |
| **1.1-C** | Auth — OAuth (Google/GitHub/Apple) + email. Sign-in flow, session in Valkey, cookie issuance. | 1.1-B schema stable |
| **1.1-D** | Coord ↔ control-plane integration. Coord's `state.json` backed by PG (or fully replaced); new device onboarding minted by the console (replaces `gnet-discover` CLI for new joins). Existing v1.0 deployments migrate via a one-shot `state.json → PG` importer. | 1.1-C auth stable |
| **1.1-E** | Console — read-only. Dashboard, fleet map, per-device drill-down with the pushed admin snapshot, metrics graphs, event stream via SSE (Valkey pub/sub). | 1.1-D integration stable |
| **1.1-F** | Console — write ops. Mint/revoke device, toggle relay-eligible, force key-rotate, edit network settings. Audit log per Network. | 1.1-E UI stable |
| **1.1-G** | `gnet.golia.jp` marketing site integration. Landing page + docs + sign-up handing off to the console. | console feature-frozen |
| **1.1-H** | Self-host packaging. Docker Compose for the axum + PG + Valkey stack; documented overrides so an operator can run the same stack on their own box. | hosted version stable |

### 2.x — wire-breaking changes (deferred)

Out-of-scope for the 1.x line; these are sized as their own major:

- **ACL / policy rules.** gnet is currently full-mesh by design;
  ACLs are a wire+coordinator change.
- **Subnet routes / exit nodes.** New wire feature, not just UI.
- **Team / Member permissions.** 1.1.0 ships single-owner networks;
  team permissions land in 1.2.0.
- **Mobile clients.** Cross-platform TUN is not on the gnet path.

## Out of scope for 1.x (deferred indefinitely)

- **Publishing the stones to crates.io.** A separate, post-1.0 track
  with its own plan. The publish topology and per-crate dry-runs
  already pass (see [crates/PUBLISH.md](crates/PUBLISH.md));
  scheduling is decoupled from the daemon tag line.
