# scripts/

Operator-side automation. **Strictly two concerns**, fully isolated:

| Concern | What | Where |
|---|---|---|
| **GitHub Actions (public-facing)** | quality gate on PR + multi-arch release pipeline on tag | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.github/workflows/release.yml`](../.github/workflows/release.yml) |
| **Internal fleet capability** | rsync + build + restart `gnet` daemon on our own SSH hosts | [`scripts/deploy-fleet.sh`](deploy-fleet.sh) — local shell |

The CI never deploys; the release pipeline never touches the fleet;
the fleet script never touches anything public.

## Fleet deploy (internal capability — never published, never automated)

```bash
# all hosts in the default set (t01 t02 lx64)
./scripts/deploy-fleet.sh all

# specific hosts
./scripts/deploy-fleet.sh t01 t02

# rollback (cp /usr/local/bin/gnet.bak → in-place + restart)
./scripts/deploy-fleet.sh --rollback t02
```

Override the default set with `ALL_HOSTS="t01 t02"` env var.

Each deploy is atomic per host: rsync source → cargo build --release →
`cp gnet → gnet.bak` → install new binary + new systemd unit →
`systemctl restart gnet@main` → `gnet doctor` verifies. A red doctor
flips the script's exit code but doesn't auto-rollback — operator
decides.

## Release pipeline (public-facing — GitHub Actions, tag-triggered)

Live at [`.github/workflows/release.yml`](../.github/workflows/release.yml).
Triggered by `git push origin gnet-vX.Y.Z`, or manually via
`gh workflow run release.yml -f tag=gnet-vX.Y.Z` against an existing
tag.

Produces, per release:

- **Binary tarballs** uploaded to the GitHub Release:
  - `gnet-vX.Y.Z-aarch64-apple-darwin.tar.gz`
  - `gnet-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
  - `gnet-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz`
- **Multi-arch Docker images** pushed to two registries:
  - `goliakk/gnet:X.Y.Z` + `goliakk/gnet:latest` (Docker Hub)
  - `ghcr.io/goliajp/gnet:X.Y.Z` + `ghcr.io/goliajp/gnet:latest` (ghcr)
  - Each image is `linux/amd64 + linux/arm64`.

Required GitHub Actions secrets (set once via `gh secret set`):

- `DOCKERHUB_USERNAME` — `goliakk`
- `DOCKERHUB_TOKEN` — a Docker Hub PAT with write access to
  `goliakk/gnet`

ghcr.io uses the built-in `GITHUB_TOKEN` automatically (the workflow's
`permissions: packages: write` clause).
