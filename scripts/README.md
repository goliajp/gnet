# scripts/

Operator-side automation. All three concerns are **strictly isolated**
— they don't share state, don't depend on each other, and live in
different files so a regression in one never affects the others:

| Concern | What | When | Where |
|---|---|---|---|
| **Product CI** | fmt + clippy + cargo test | PR + manual | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — runs on GitHub Actions |
| **Fleet deploy** | Build + install + restart `gnet` daemon on internal SSH hosts | After a tag, by hand | [`scripts/deploy-fleet.sh`](deploy-fleet.sh) — local shell, ssh out |
| **Docker publish** | Build + push `goliakk/gnet` to Docker Hub | After a tag, by hand | [`scripts/docker-publish.sh`](docker-publish.sh) — local shell + `docker login` |

The CI never deploys; the deploy never touches Docker; the Docker
publish never touches the fleet.

## Fleet deploy

```bash
# all hosts in the default set (t01 t02 lx64)
./scripts/deploy-fleet.sh all

# specific hosts
./scripts/deploy-fleet.sh t01 t02

# rollback (cp /usr/local/bin/gnet.bak → in-place + restart)
./scripts/deploy-fleet.sh --rollback t02
```

Override the default set with `ALL_HOSTS="t01 t02"` env var.

Each deploy is atomic per host: rsync source → cargo build --release
→ `cp gnet → gnet.bak` → install new → `systemctl restart gnet@main`
→ `gnet doctor` verify. A red doctor flips the script's exit code but
doesn't auto-rollback — operator decides.

## Docker publish

```bash
# one-time
docker login -u goliakk
# (paste Hub PAT when prompted)

# every release
./scripts/docker-publish.sh 1.0.0
./scripts/docker-publish.sh 1.0.0 --also-latest   # also push :latest

# image lands at https://hub.docker.com/r/goliakk/gnet
```

The script warns (doesn't block) if HEAD has no tag or the working
tree is dirty — sometimes you do want to publish a snapshot
deliberately. The PAT never enters this repo — it lives in
`~/.docker/config.json` after `docker login`.

Multi-arch (linux/amd64 + linux/arm64) is a `docker buildx` extension
left as a follow-up; the v1.0.0 audience is x86_64.

## When to add a new concern

If a fourth concern shows up (e.g. coordinator deploy,
relay-server deploy, marketing-site deploy), it gets its own
script + its own one-liner in this README. **Don't fold it into one
of the existing three** — the isolation property is the point.
