# Publishing the `gnet-*` crates to crates.io

This document describes the topological order in which the 9 publishable
crates must be uploaded to crates.io. Internal cross-references are
declared in the workspace root's `[workspace.dependencies]` table with
both `path` (resolves locally during development) and `version`
(takes effect at publish time). Internal **dev-deps** are kept as plain
`{ path = "../foo" }` without a `version` field so `cargo publish`
strips them from the uploaded manifest entirely — dev-deps are
local-test-only and the consumer build does not need them on the
registry.

## Daemons / harness crates — not published

These compile to binaries and stay in-repo:

- `gnet` — daemon binary
- `gnet-discover` — coordinator daemon binary
- `gnet-bench-compare` — internal side-by-side benchmark harness
- `server` — portal-server backend (separate concern)

## Publishable topological order

`cargo publish --dry-run --no-verify -p <crate>` verifies the manifest
without requiring deps to already exist on crates.io. All nine crates
below currently pass that check.

```
Tier 0 (no internal deps):
  1. gnet-rand                  OS entropy wrapper
  2. gnet-hex                   lowercase hex encode/decode
  3. gnet-wire                  1-byte tag framing
  4. gnet-tun                   utun / Linux tun device
  5. gnet-crypto                ChaCha20-Poly1305 / X25519 / BLAKE2s / HKDF / SHA-3 / ML-KEM-768

Tier 1 (depends on Tier 0):
  6. gnet-noise                 Noise_IK + ML-KEM-768 hybrid handshake (needs gnet-crypto)
  7. gnet-punch                 DCUtR rendezvous codec + state machine (needs gnet-wire)
  8. gnet-relay                 DERP-like envelope framing (no real internal deps; ships standalone)

Tier 2 (depends on Tier 0 + 1):
  9. gnet-config                WireGuard-style config parser (needs gnet-crypto, gnet-hex)
```

Strict ordering only matters for the **first** publish (each tier must
be on crates.io before the tier above can be published). After that,
patch versions can be uploaded independently as long as the inter-crate
version constraints in workspace.dependencies stay consistent.

## Publishing checklist (per crate)

Before any `cargo publish`:

1. `cargo test --workspace --lib` — all green
2. `cargo clippy --workspace --all-targets` — clean under
   `deny(warnings)` + `deny(clippy::all)`
3. `cargo doc --no-deps -p <crate> --open` — read the rendered docs
4. `cargo publish --dry-run --no-verify -p <crate>` — manifest sanity
5. Bump `[workspace.package].version` in the root `Cargo.toml`
   (cascades to every crate via `version.workspace = true`)
6. Sync the bump into `[workspace.dependencies]`'s inter-crate
   `version = "..."` fields
7. Update each crate's `CHANGELOG.md` `[Unreleased]` → new version
   heading
8. Tag the release: `git tag -a v<version> -m "<release notes>"`
9. `cargo publish -p <crate>` in topological order

## Version pinning model

- `[workspace.package].version` is the single source of truth.
- Every crate's `version.workspace = true` inherits it.
- `[workspace.dependencies].gnet-*` `version = "..."` fields must
  match `[workspace.package].version` exactly. A bump touches both.

This keeps the dep graph internally consistent: a fresh checkout
builds locally via `path`, while a downloaded crate from crates.io
pulls the exact matching internal-crate version.
