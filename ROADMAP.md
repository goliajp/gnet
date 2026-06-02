# gnet roadmap

> The destination and the version boundary. Step-level plans live per
> checkpoint, not here — this document fixes *what* 1.0 is and *what order*
> the work lands in, deliberately without per-step detail.

## Where we are

- **Tag line:** `gnet-v0.21` (daemon/system milestones), deployed to the
  internal fleet on 2026-06-02 and operating green. Track A is
  feature-complete as of v0.20 — A6 coordinator state sync/failover with a
  read-only warm-standby fence (v0.18–v0.19), discovery peer-leave, and relay
  health probing/failover (v0.20). Track C observability landed in v0.21:
  admin unix-socket IPC, fused live state in `gnet status`, and a Prometheus
  exporter (`gnet metrics`). The v0.21 deploy also exposed and fixed a
  pre-existing sandbox interaction with `/etc/hosts` (hosts.rs now falls back
  to a direct truncate+write_all when tmp+rename is blocked, with the systemd
  unit widened by exactly one entry). At this point the project is
  **operationally self-sufficient for internal use**; remaining tracks
  (B quality gate, E open-source presentation) are the public-release gates,
  and a web admin panel is scoped to land in **v1.1**, decoupled from the
  v1.0 public-flip. The 9 data-plane library crates ("stones") carry the
  workspace version `2.0.0-alpha.2`, inherited verbatim from the pre-split
  portal monorepo.
- Standalone workspace since the split from `goliajp/portal`. Runs
  internally on a small fleet (macOS arm64, Linux x86_64, AWS Graviton
  aarch64).
- Data plane is zero-dependency and KAT-validated; control plane
  (`gnet-discover`) and the standalone `gnet-relay-server` are wired into
  the active path as of v0.17.

## What "gnet 1.0" means

**gnet 1.0 is the milestone where the project goes public on GitHub** as a
feature-complete, observable, well-documented system that holds up to
outside scrutiny. It is a git tag `gnet-v1.0` on the existing daemon tag
line — **not** a crates.io release.

Publishing the stones to crates.io is **decoupled and deferred** (see
*Out of scope* below). The daemon binaries (`gnet`, `gnet-discover`,
`gnet-relay-server`, `gnet-bench-compare`) are never published to crates.io
— they ship as a public GitHub repository.

## Scope — the v1.0 boundary (fixed)

Four tracks. Work units are stated at the *what / why / what-it-needs*
level; the executable step plan for each is written only when its
checkpoint goes hot.

### Track A — daemon feature-complete (fleet reliability)

- **A6 — coordinator state sync / failover.** `state.json` consistency
  across the primary + backup coordinator so a coordinator restart or
  failover does not lose or fork device state.
- **Node → relay-server registration keepalive.** Idle nodes stay reachable
  through a relay server even when they have not recently originated
  RelayData (today the relay only knows a peer after it speaks first).
- **Relay reliability / multi-relay selection.** v0.17 picks
  `relay_servers.first()`; 1.0 wants sane selection (reachability / RTT /
  region) and graceful behaviour when a relay is down.
- **Peer-leave / removal.** Discovery never removes vanished peers today
  (a known, deliberately-deferred gap). 1.0 closes it.

### Track B — quality signals (holds up to public scrutiny)

Not a crates.io gate anymore — these are the credibility backing for an
open-source release.

- **KAT audit + freeze.** Primitives already carry inline known-answer
  tests; audit coverage, align with official RFC/NIST vectors, freeze as
  committed regression fixtures.
- **Fuzzing harness.** `cargo-fuzz` targets for the untrusted-input
  surfaces: wire parse, config parse, relay decode, Noise message parse.
- **SECURITY.md.** Disclosure policy + contact — table stakes for a public
  repo.
- **Constant-time / side-channel review** of the crypto hot paths.

### Track C — observability

- Structured event log exists (A4). Add a metrics surface, health checks
  (coordinator already has `/healthz`), `gnet status` enrichment, and
  enough signal that a fleet fault is locatable without shell archaeology.

### Track E — open-source presentation (the gate for going public)

- **This roadmap** (now landed).
- **Enable CI.** `ci.yml` exists but GitHub Actions does not run it; turn it
  on and **pin the rustfmt version** (the workspace HEAD was committed with
  an older rustfmt; an unpinned `cargo fmt` reorders ~39 files — see the CI
  notes). A public repo needs green checks on every PR.
- **CONTRIBUTING.md**, issue/PR templates, README polish.
- **Deploy docs** beyond `linux-systemd` — macOS, coordinator, relay-server.

### Track F — small polish (lands between v0.21 and the public flip)

- **`gnet doctor`** — operator diagnostic subcommand: probe coordinator
  reachability, admin socket bind, relay health, conf sanity (overlap with
  `gnet status` is intentional — `doctor` is the "pre-flight + green/red
  verdict", `status` is the "full picture").
- **Small bug-fixes surfacing from fleet operation** — caught by `journalctl
  | grep event=` audits during the observation window.

## Sequencing & triggers

Versions are indicative, not contractual; the *order* is the commitment.
**Observation periods between minor versions (x.y.z, only y/z changing) are
not part of the cadence** — checkpoints flow into each other directly. Only
a **major bump** (x → x+1, e.g. v0.x → v1.0 or v1.x → v2.0) earns a
deliberate observation window before the next major work starts.

A6 split into two checkpoints (state sync/failover, then the read-only standby
fence), which pushed the later checkpoints down one slot from the original
plan — versions are indicative, so the numbers shifted while the track order
held.

| Checkpoint | Content | Trigger to go hot | Status |
|---|---|---|---|
| **v0.18** | Track A: A6 state sync/failover + relay registration keepalive | v0.17 shipped + deferred items named | ✓ shipped |
| **v0.19** | Track A: A6 warm-standby read-only fence (failover self-consistent, no silent data loss on primary recovery) | A6 core landed | ✓ shipped |
| **v0.20** | Track A remainder: discovery peer-leave/reconcile + relay health probing & failover (keepalive echo) | v0.18–v0.19 verified stable on the fleet | ✓ shipped |
| **v0.21** | Track C observability: admin unix-socket IPC, `gnet status` live fusion (session/path/last-handshake per peer), `gnet metrics` Prometheus exporter, counters at handshake/relay-register/relay-fallback. Wire untouched. | v0.20 fleet-stable + relay echo validated | ✓ shipped 2026-06-02 |
| **v0.22** | Track F polish — `gnet doctor` diagnostic subcommand + small fleet-surfaced bug-fixes | v0.21 deployed | ✓ shipped 2026-06-03 (doctor; further fleet-surfaced fixes folded as they appear) |
| **v0.23** | Track B quality gate (KAT freeze, fuzzing, SECURITY.md, CT review) | v0.22 doctor lands; no wire changes planned for v1.0 | ✓ shipped 2026-06-03 |
| **v0.24** | Track E presentation (CI enable, **always-latest toolchain policy**, CONTRIBUTING, deploy docs, README, codebase reflow against current rustfmt) | quality gate green | ✓ code shipped 2026-06-03 — toolchain policy locked in as "always latest stable" (rust-toolchain channel = "stable"; CI uses `dtolnay/rust-toolchain@stable`); no version-pinning. **One operator action left:** GitHub Actions is currently registered only for the dependabot "Dependency Graph" workflow; `ci.yml` is committed but not picked up. Likely a repo Settings → Actions → General toggle needs flipping (the API rejects automated enable from non-admin tokens). Once Actions is on, the existing `ci.yml` runs on every push without further change. |
| **gnet-v1.0** | Flip the GitHub repo to public; tag the release | all four tracks green + CI running. **Major bump — earns an observation window before v1.1 control-plane work begins.** | |
| **v1.1 (post-public)** | Control plane + console at gnet.golia.jp — account model, OAuth, Tailscale-style fleet UI. Separate project (Rust + axum + PG18 + Valkey9 + React 19). See "Post-1.0 plan" below. | v1.0 tagged + public; observation window passed | planned |

## Post-1.0 plan — v1.1 control plane + console (gnet.golia.jp)

v1.1 is the **public control plane**: a Tailscale-style account-and-network
SaaS surface, integrated with the public marketing site at
`gnet.golia.jp`. Account-aware: one user owns N networks; each network owns
N devices. Sign in with Google / GitHub / Apple, or email. The console
gives the same Tailscale-shape capabilities — fleet view, per-device
drill-down, mint/revoke device tokens, toggle relay-eligible, force
key-rotate, live event stream.

This is a **separate project** in scope (probably its own repo: web
codebase, schema migrations, OAuth secrets, hosted infra) and explicitly
not the small "embedded admin panel next to the coordinator" sketched in
earlier roadmap revisions. The earlier `gnet-admin` mini-binary sketch is
**superseded** by this plan; do not build the mini-binary as an interim
step — its data model would be thrown away.

### Architectural ground rules (non-negotiable)

- **Separate project, separate process, separate deploy.** The control
  plane lives apart from `gnet` and `gnet-discover` — a control-plane
  outage must not stop existing devices from talking. Once a device is
  registered, day-to-day overlay traffic uses only the cached coord roster
  and direct/relay paths; the control plane is for onboarding, observing,
  and policy edits, not for the data path.
- **Authoritative state in Postgres.** The current `state.json` becomes a
  cache / projection; user/account/network/device records live in PG.
- **Coordinator stays the fan-in for node telemetry**, but its backing
  store moves from a JSON file to PG (via the control plane's DB). The
  push channel (v1.1-A) writes node snapshots through the coord into PG,
  and the console reads from PG.
- **Zero-deps daemon stays zero-deps.** The push channel is one new POST
  in the daemon; no SDK, no proto compiler.
- **Self-host is supported but not the default path.** A solo operator can
  still run the full stack on one box (axum + PG + Valkey via Docker
  Compose). The hosted path at gnet.golia.jp is the SaaS-style default.

### Account model

- **User** — auth identity. Has zero or more **OAuthIdentity** rows
  (provider ∈ {google, github, apple}, provider_subject), and optionally
  an email/password credential.
- **Network** (analogous to a Tailscale "tailnet"): a logical mesh with
  its own overlay subnet, its own relay servers, its own coord. A user
  may own multiple networks (personal + work).
- **Device** — a `gnet` daemon. Belongs to exactly one Network. Carries
  its X25519 pubkey, ML-KEM ek, current device_token, last reflexive
  endpoint, current alias, current overlay vIP.
- **Member** (deferred to v1.2): a User who is granted access to another
  User's Network. v1.1 ships with single-owner networks only — keeps the
  permission model trivial for the first cut.

### Tech stack

- **Backend:** Rust + axum, Postgres 18 (main store), Valkey 9 (session
  store + rate-limit counters + SSE fan-out). New repo, not in this
  workspace.
- **Frontend:** React 19 + Vite 7 + Tailwind CSS 4 + react-router +
  `@tanstack/react-query` + Jotai (atoms). Built via the `frontend-design`
  plugin's design system. SPA, CSR.
- **Auth:** OAuth (Google / GitHub / Apple) + email/password. Sessions in
  Valkey, cookie-based. Device credential remains the existing
  `device_token` (now bound to a Network's Device row in PG instead of a
  coord-side `state.json` entry).
- **TLS / hosting:** behind Caddy on gnet.golia.jp. Public site +
  console served from the same domain (console at `/app` or
  `console.gnet.golia.jp`).

### Phase breakdown (indicative — each goes hot when its trigger fires)

| Checkpoint | Content | Trigger |
|---|---|---|
| **v1.1-A** | **Node → coord push channel.** Daemon POSTs admin snapshot + new events to coord every N seconds (or on event-emit, batched). Coord keeps latest snapshot per device + ring buffer. Existing GET /peers poll unchanged. | v1.0 public + observation window |
| **v1.1-B** | **Account/Network/Device schema in PG18 + axum scaffolding.** User, OAuthIdentity, Network, Device tables; baseline axum app; health check; DB migrations harness. | v1.1-A push data shape stable |
| **v1.1-C** | **Auth — OAuth (Google/GitHub/Apple) + email.** Sign-in flow, session in Valkey, cookie issuance. | v1.1-B schema stable |
| **v1.1-D** | **Coord ↔ control-plane integration.** Coord's `state.json` backed by PG (or fully replaced); existing `device_token` flow goes through the control plane's API; new device onboarding minted by the console (replaces `gnet-discover` CLI for new joins). Existing v1.0 deployments migrate via a one-shot `state.json → PG` importer. | v1.1-C auth stable |
| **v1.1-E** | **Console — read-only.** Dashboard, fleet map, per-device drill-down with the pushed admin snapshot, metrics graphs (recharts or similar), event stream via SSE (Valkey pub/sub). | v1.1-D integration stable |
| **v1.1-F** | **Console — write ops.** Mint/revoke device, toggle relay-eligible, force key-rotate, edit network settings. Audit log per Network. | v1.1-E UI stable |
| **v1.1-G** | **gnet.golia.jp marketing site integration.** Landing page + docs + sign-up flow handing off to the console. | console feature-frozen |
| **v1.1-H** | **Self-host packaging.** Docker Compose for the axum + PG + Valkey stack; documented `coord_url` / `oauth_*` overrides so an operator can run the same stack on their own box. | hosted version stable |

### Out of scope for v1.x (still deferred to v2.x)

- **ACL / policy rules.** gnet is currently full-mesh by design; ACLs are
  a wire+coordinator change, far beyond a console addition.
- **Subnet routes / exit nodes.** New wire feature, not just UI.
- **Team / Member permissions.** v1.1 ships single-owner networks; team
  permissions land in v1.2.
- **Mobile clients.** Cross-platform TUN is not on the gnet path.

## Out of scope for 1.0 (deferred)

- **Publishing the stones to crates.io.** A separate, post-1.0 track with
  its own plan. The publish topology and per-crate dry-runs already pass
  (see `crates/PUBLISH.md`); when it happens, the stones' crates.io semver
  is decided then — independent of the `gnet-v*` system tag line. The
  carried-over `2.0.0-alpha.2` workspace version only matters at that point.
- **Web admin panel.** Scoped as v1.1 (see "Post-1.0 plan" above). v1.0
  ships as CLI + Prometheus exporter; the panel is the v1.1 differentiator.
