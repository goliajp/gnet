# gnet roadmap

> The destination and the version boundary. Step-level plans live per
> checkpoint, not here — this document fixes *what* 1.0 is and *what order*
> the work lands in, deliberately without per-step detail.

## Where we are

- **Tag line:** `gnet-v0.17` (daemon/system milestones). The 9 data-plane
  library crates ("stones") carry the workspace version `2.0.0-alpha.2`,
  inherited verbatim from the pre-split portal monorepo.
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

## Sequencing & triggers

Versions are indicative, not contractual; the *order* and the *trigger* are
the commitment. A checkpoint goes hot only when its trigger is observed.

| Checkpoint | Content | Trigger to go hot |
|---|---|---|
| **v0.18** | Track A core: A6 state sync/failover + relay keepalive | v0.17 shipped + deferred items named — **met now** |
| **v0.19** | Track A remainder (relay reliability, peer-leave) + Track C observability | v0.18 verified stable on the fleet |
| **v0.20** | Track B quality gate (KAT freeze, fuzzing, SECURITY.md, CT review) | daemon feature-frozen, no pending wire changes |
| **v0.21** | Track E presentation (CI enable, rustfmt pin, CONTRIBUTING, deploy docs, README) | quality gate green |
| **gnet-v1.0** | Flip the GitHub repo to public; tag the release | all four tracks green + CI running |

## Out of scope for 1.0 (deferred)

- **Publishing the stones to crates.io.** A separate, post-1.0 track with
  its own plan. The publish topology and per-crate dry-runs already pass
  (see `crates/PUBLISH.md`); when it happens, the stones' crates.io semver
  is decided then — independent of the `gnet-v*` system tag line. The
  carried-over `2.0.0-alpha.2` workspace version only matters at that point.
