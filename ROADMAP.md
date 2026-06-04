# gnet roadmap

> The destination and the version boundary. This document fixes *what
> the next major / minor releases contain* and *what order* the work
> lands in — deliberately without per-step detail. Step-level plans
> live per checkpoint.

## Where we are

- **Tag line:** `v1.1.0`, released 2026-06-04. Workspace version
  unified at `1.1.0`. v1.0 cuts (`v1.0.0` 2026-06-03 → `v1.0.2`
  2026-06-03) covered the data-plane / coord baseline; v1.1.0 is
  the control-plane release on top.
- Internal fleet (macOS arm64 + Linux x86_64 + AWS Graviton aarch64)
  running v1.1.0; data plane wire-stable with v1.0 (a v1.0 daemon on
  a v1.1 fleet keeps running unaware of the new admin surface).
- Data plane: zero-deps, post-quantum hybrid Noise_IK + ML-KEM-768,
  KAT-validated against RFC/NIST/ACVP vectors, CT-audited
  (see [CT-REVIEW.md](crates/gnet-crypto/CT-REVIEW.md)),
  fuzz-harnessed (see [fuzzing.md](docs/fuzzing.md)).
- Control plane: PG-backed dispatcher with an admin API + embedded
  SPA, SaaS console at `gnet.golia.jp` federating to user
  dispatchers via deterministic-token federation, lite admin
  surfaces on the relay and (opt-in) the daemon. Container layout
  collapsed to one image — `goliakk/gnet` (also on ghcr) — that
  dispatches by `GNET_ROLE` to daemon / dispatcher / relay / console.
- CI green on `develop`; toolchain policy is **always latest stable**
  (`rust-toolchain.toml` channel = "stable"; CI
  `dtolnay/rust-toolchain@stable`). GH Actions runtime is Node 24
  (`actions/{checkout,upload-artifact,download-artifact}@v5`).

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

### 1.1.x — patch lane (current)

Bug-fixes, doc, CI hardening, plus the v1.1 backlog items that
are independent slices and don't need v1.2's release boundary:

- **OAuth provider creds wired through** — Google / GitHub / Apple
  OAuth clients registered, `OAUTH_*` env added to t01 `.env`, SPA
  Login / Signup gains real provider buttons. Code surface is
  already shipped in v1.1 (`§17.5b/c/d`); only the secrets are
  outstanding.
- **Wildcard `*.gnet.golia.jp`** when multi-tenant per-network UX
  ships against Mode A. Needs Caddy DNS-01 challenge + zone PUT
  to devops DNS API.
- **Dedicated mailrs service account** in place of the superadmin
  login the v1.1 console currently uses.
- Fleet-surfaced bugs caught by `journalctl | grep event=` during
  the v1.1 observation window.

### 1.0.x — patch lane (historical, closed)

Closed with `v1.0.2` (2026-06-03). The active patch lane is 1.1.x.

### 1.1.0 — SaaS control plane + console at gnet.golia.jp ✅ shipped 2026-06-04

> Released 2026-06-04 as `v1.1.0`; the engineering plan lived at
> [docs/v1.1-plan.md](docs/v1.1-plan.md) and the slice-level changes
> are in the [CHANGELOG `[1.1.0]`](CHANGELOG.md#110---2026-06-04)
> entry. Below is the original phase contract for archival
> reference.

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

### 1.2.0 — control channel + native app + members + ASVS L1 finish

The three loops v1.1 deliberately left open, closed in one
release. Detailed engineering plan lives at
[docs/v1.2-plan.md](docs/v1.2-plan.md); summary phase table:

| Phase | Content | Trigger |
|---|---|---|
| **1.2-A1** | `device_pending_ops` schema + snapshot-reply control channel; daemon JSON parse + ack endpoint | v1.1 dogfood passed |
| **1.2-A2** | Dispatcher write paths `rotate-key` + `restart` flip from `501` to enqueueing real ops on 1.2-A1 | 1.2-A1 stable |
| **1.2-A3** | Daemon `/local/{alias,join,quit,restart,upgrade}` real implementations + supervisor (launchd / systemd) integration | 1.2-A1 stable |
| **1.2-A4** | `mac/` SwiftUI menubar app — read-only first cut against `/local/status` | 1.2-A3 GET surface stable |
| **1.2-A5** | macOS menubar app writes + signed/notarised `.dmg` + install script + `release.yml` matrix entry | 1.2-A3/A4 stable |
| **1.2-B1** | `network_members` + `network_invitations` schema + member-aware `require_login` | independent |
| **1.2-B2** | Member invite + accept flow + mailrs email + SPA invite UI | 1.2-B1 + mailrs (v1.1) |
| **1.2-B3** | Role enforcement on every write handler; `audit_log.actor_role` recorded | 1.2-B1 |
| **1.2-C1** | CSP + Permissions-Policy + per-route body limits | independent |
| **1.2-C2** | Per-IP login throttle + signup CAPTCHA | independent |
| **1.2-C3** | `audit_log` hash chain + `GET /api/audit/verify` | independent |

Tracks A / B / C are loosely coupled. Cut-over to v1.2 needs all
three green on the internal fleet.

### 2.x — wire-breaking changes (deferred)

Out-of-scope for the 1.x line; these are sized as their own major:

- **ACL / policy rules.** gnet is currently full-mesh by design;
  ACLs are a wire+coordinator change.
- **Subnet routes / exit nodes.** New wire feature, not just UI.
- ~~**Team / Member permissions.**~~ Moved into 1.2.0 (B-track).
- **Cross-platform native clients (Linux GUI / Windows).** The
  daemon's `/local/*` admin surface is portable, so a third-party
  client on any OS is unblocked once they implement against it.
  We ship macOS in 1.2.0; Linux / Windows official clients are
  2.x candidates.
- **Mobile clients.** Cross-platform TUN remains off the gnet
  path; mobile is 2.x unless a target-OS-side surface lands that
  changes the calculation.

## Out of scope for 1.x (deferred indefinitely)

- **Publishing the stones to crates.io.** A separate, post-1.0 track
  with its own plan. The publish topology and per-crate dry-runs
  already pass (see [crates/PUBLISH.md](crates/PUBLISH.md));
  scheduling is decoupled from the daemon tag line.
