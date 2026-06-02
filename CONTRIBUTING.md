# Contributing to gnet

Thanks for looking. This file covers the practical bits: how the repo is
laid out, what the dev loop is, the non-negotiable invariants, and how
to send a change.

## Repo layout

```
crates/
  gnet/                # the daemon binary + library (`gnet up`, `gnet status`, …)
  gnet-discover/       # coordinator (control plane, HTTP/1.1)
  gnet-relay-server/   # standalone UDP relay daemon
  gnet-bench-compare/  # internal perf gate vs SOTA Rust ecosystem competitors
  gnet-crypto/         # ChaCha20-Poly1305, X25519, BLAKE2s, HKDF, SHA-3, ML-KEM-768
  gnet-noise/          # Noise_IK + the ML-KEM hybrid pattern
  gnet-wire/           # UDP datagram framing
  gnet-relay/          # relay envelope
  gnet-punch/          # DCUtR + symmetric-NAT port-prediction
  gnet-tun/            # OS TUN device FFI
  gnet-rand/           # OS entropy
  gnet-hex/            # lowercase hex codec
  gnet-config/         # multi-peer conf parser
docs/                  # roadmap-adjacent narrative + per-topic deep dives
ROADMAP.md             # the destination + version boundary
SECURITY.md            # disclosure policy + threat model
```

The nine **data-plane "stones"** (`gnet-crypto`, `gnet-noise`,
`gnet-wire`, `gnet-relay`, `gnet-punch`, `gnet-tun`, `gnet-rand`,
`gnet-hex`, `gnet-config`) carry the **zero-dependency** invariant —
no `crates.io` dependencies whatsoever, at any version. Adding a dep
to one of those crates is a release-breaking change.

The daemon binary crates (`gnet`, `gnet-discover`, `gnet-relay-server`)
may add dependencies cautiously when the win is meaningful (e.g. `tokio`
+ `serde` in `gnet-discover` for the HTTP coordinator).

## Dev loop

You will need a Rust toolchain — see `rust-toolchain.toml` (currently
`channel = "stable"`; this will pin to a specific minor in v0.24).

```bash
# fast inner loop
cargo build
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# perf gate (release-mode only — debug builds are noise)
cargo test --release -p gnet-bench-compare

# fuzz harnesses (requires nightly + cargo-fuzz) — see docs/fuzzing.md
cd crates/gnet-wire && cargo +nightly fuzz run wire_parse -- -max_total_time=10
```

`cargo test --workspace` runs everything in seconds; clippy is the
main "did I add a smell" gate. Both must be green to land a PR.

## Non-negotiable invariants

1. **Zero deps on the nine stones.** See above. CI runs
   `cargo publish --dry-run` on the Tier-0 leaf crates to catch
   accidental deps.

2. **Wire compatibility within a minor version.** A v0.23.x deploy
   must keep working when a v0.23.y daemon joins the mesh. Breaking
   the wire takes a minor bump (and a CHANGELOG note).

3. **Crypto changes need KAT + CT review.** Anything touching
   `crates/gnet-crypto/` updates
   [`KAT.md`](crates/gnet-crypto/KAT.md) if vectors move and
   [`CT-REVIEW.md`](crates/gnet-crypto/CT-REVIEW.md) if a
   secret-dependent code path changes. Wire-compat verdict goes in the
   commit body (ours is always "wire unchanged" for CT fixes).

4. **Daemon is best-effort on observability.** A bug in the
   admin-socket / metrics / event-log path must not block the wire
   path. The pattern is `eprintln!("event=…_failed …")` + continue,
   never `panic!` / `?` out of the pump.

5. **Operator-facing outputs are diffable.** `gnet status`,
   `gnet doctor`, and `gnet metrics` print stable, line-oriented
   output so `diff` between runs / between hosts is a usable triage
   tool.

## Commit style

Conventional-ish, but more descriptive bodies than the conventional
spec asks for:

- Subject: `<scope>: <imperative summary>` — `<scope>` is the crate
  (`gnet`, `gnet-discover`, …) or `docs` / `chore` / `fix`. Past
  shipped commits in `git log` are the reference.
- Body: explain the *why*, the *constraint that drove the design*,
  and any *wire / CT / KAT verdict*. Don't restate the diff — git
  already shows that.
- Trailer: `Co-Authored-By:` for paired work (humans + AI agents both
  use this convention here).

Example (a real shipped commit):

```
fix: mlkem decaps FO mask via wrapping_sub, not if-else (v0.23 Track B CT review)

CT review surfaced one real bool-boundary slip … The `if ok` form may
compile to a conditional jump on some backends — leaking the FO check
outcome through timing, which is exactly what the implicit-rejection
key is supposed to hide. Replaced with `(ct_eq(...) as u8).wrapping_sub(1)`
which compiles to unconditional cmp+sete+sub on every backend gnet
targets. Wire-format unchanged; ML-KEM ACVP tests still pass.

[…]
```

## PR flow

1. Branch from `develop` (default branch is `develop` until v1.0).
2. One concern per PR. Multi-topic PRs get split on review.
3. Open the PR with the commit body as the description (or a
   subset — the commit is the canonical place for engineering
   detail; the PR description is for review-time context).
4. CI runs `fmt --check`, `clippy -D warnings`, `cargo test`,
   `cargo doc`, the perf gate (non-blocking — known noise on shared
   runners), `cargo run --example` smoke tests on each
   public-example, and `cargo publish --dry-run` on the leaf crates.
   All required checks must be green.
5. Squash or rebase before merge — the develop history reads
   linearly. No merge commits into develop.

## Adding a new crate

Three checklists:

- **Data-plane stone (must be zero-deps).** Add to `crates/`, add to
  `members` in the workspace `Cargo.toml`, add to `workspace.dependencies`
  with `path` + `version`, append to `crates/PUBLISH.md` with its
  topological tier. Add a fuzz harness if it parses untrusted input
  (see [docs/fuzzing.md](docs/fuzzing.md)).
- **Daemon binary.** Add to `crates/`, add to workspace `members`,
  write a unit file in `crates/<name>/deploy/` (Linux) /
  `contrib/launchd/` (macOS), write the deploy doc under `docs/deploy/`.
- **Internal-only crate (like `gnet-bench-compare`).** Add to
  `crates/`, mark `publish = false` in its `Cargo.toml`, exclude
  from the publish topology in `crates/PUBLISH.md`.

## Adding a fuzz target

See [`docs/fuzzing.md`](docs/fuzzing.md) — short version: write a
`fuzz_target!` in `crates/<name>/fuzz/fuzz_targets/`, set
`[workspace]` in the fuzz Cargo.toml (so it stays out of the main
workspace), smoke-run for 10 seconds, append a row to the table.

## Reporting security issues

See [SECURITY.md](SECURITY.md). The short version: email
`security@golia.jp`, do not file public issues for unpatched findings,
expect a 3-business-day ack and 10-business-day triage.

## Code of conduct

Be excellent. Disagreement on technical merits is welcome and
expected; disagreement that targets the contributor instead of the
contribution isn't.
