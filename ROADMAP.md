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

Versions are indicative, not contractual; the *order* and the *trigger* are
the commitment. A checkpoint goes hot only when its trigger is observed.

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
| **v0.22** | Track F polish — `gnet doctor` diagnostic subcommand + small fleet-surfaced bug-fixes | v0.21 deploy stable + 1-2 weeks of fleet operation observed | next |
| **v0.23** | Track B quality gate (KAT freeze, fuzzing, SECURITY.md, CT review) | daemon feature-frozen, no wire changes planned for v1.0 | |
| **v0.24** | Track E presentation (CI enable, rustfmt pin, CONTRIBUTING, deploy docs, README) | quality gate green | |
| **gnet-v1.0** | Flip the GitHub repo to public; tag the release | all four tracks green + CI running | |
| **v1.1 (post-public)** | Web admin panel — see "Post-1.0 plan" below | v1.0 tagged + public; observation window passed | planned |

## Post-1.0 plan — v1.1 web admin

A Tailscale-style web panel: fleet view, per-device drill-down, operator
actions (mint/revoke token, toggle relay-eligible, force key-rotate), and a
live event stream. Sized as a **post-1.0** feature on purpose — the v1.0
public-flip ships as a CLI + Prometheus story, and the web admin is the
v1.1 differentiator.

### Architectural ground rules (non-negotiable)

- **Separate process from `gnet` and `gnet-discover`.** The admin panel is
  optional supporting infrastructure — a crash or maintenance window must
  not affect the overlay daemon, the coordinator, or any CLI surface.
- **No new dependency from the daemon binary.** The push channel (v1.1-A)
  adds a small node→coord HTTP POST; the daemon stays zero-deps.
- **Coordinator is the aggregation point.** The web admin process talks to
  the coordinator's HTTP API (read + ops) and never connects directly to
  per-node admin sockets — that decoupling is what makes the admin process
  optional.
- **Authoritative state stays in the coordinator's `state.json`.** The
  admin process holds no durable state of its own; restarting it is a
  zero-data-loss operation.
- **Deploy target:** `t01` initially (lives next to the coordinator), but
  the process is location-independent — operator can move it to a separate
  host later by changing its `coordinator_url` directive.

### Tech stack

- **Backend:** new `gnet-admin` binary in a new `crates/gnet-admin/` crate.
  Same minimal-HTTP style as `gnet-discover`. Bundles the SPA assets via
  `include_dir!` so deploy stays single-binary.
- **Frontend:** React 19 + Vite 7 + Tailwind CSS 4 + react-router +
  `@tanstack/react-query` + Jotai (atoms). Built via the `frontend-design`
  plugin's design system. SPA, CSR only — SSR not justified for a private
  fleet panel. Build artifacts checked into `crates/gnet-admin/web/dist/`
  and embedded at compile time.
- **Auth:** single `admin_token` directive in the coordinator's conf. Web
  admin process forwards `Authorization: Bearer <token>` to coordinator;
  user-facing login sets a same-site cookie. Per-user accounts are
  out-of-scope (self-use, single trusted operator).
- **TLS:** reverse-proxied (Caddy/nginx). Admin process listens on
  127.0.0.1:<port> only; nothing speaks TLS itself.

### Phase breakdown

| Checkpoint | Content | Trigger |
|---|---|---|
| **v1.1-A** | **Node → coord push channel.** Daemon POSTs admin snapshot + new events to coord every N seconds (or on event-emit, batched). Coord keeps latest snapshot per device + ring buffer of recent events. Existing GET /peers poll unchanged. | v1.0 public + observation window |
| **v1.1-B** | **Coordinator admin API.** New routes: `/admin/fleet`, `/admin/devices/<id>`, `/admin/events` (SSE stream), `/admin/ops/*` (mint-token, revoke, toggle-relay, force-rotate). Bearer-auth via `admin_token`. | v1.1-A landed, push data flowing |
| **v1.1-C** | **`gnet-admin` binary + read-only SPA.** Dashboard, fleet map, per-device drill-down with live admin snapshot, embedded metrics graphs (recharts), event stream via SSE. No writes. | v1.1-B API stable |
| **v1.1-D** | **Ops integration.** Wire write actions through the v1.1-B endpoints; coord persists changes to `state.json`, nodes pick up on next poll. Audit log in coord. | v1.1-C UI stable |

### Out of scope for v1.x web admin (deferred to v2.x)

- **ACL / policy rules editor.** gnet is currently full-mesh by design;
  ACLs would be a wire+coordinator change, far beyond a UI addition.
- **Subnet routes / exit nodes.** Same — new wire feature, not just UI.
- **Multi-org / multi-tenant.** Self-use, single operator — over-engineered.
- **Mobile clients.** Cross-platform TUN is not on the gnet path.

## Out of scope for 1.0 (deferred)

- **Publishing the stones to crates.io.** A separate, post-1.0 track with
  its own plan. The publish topology and per-crate dry-runs already pass
  (see `crates/PUBLISH.md`); when it happens, the stones' crates.io semver
  is decided then — independent of the `gnet-v*` system tag line. The
  carried-over `2.0.0-alpha.2` workspace version only matters at that point.
- **Web admin panel.** Scoped as v1.1 (see "Post-1.0 plan" above). v1.0
  ships as CLI + Prometheus exporter; the panel is the v1.1 differentiator.
