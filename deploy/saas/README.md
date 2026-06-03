# gnet SaaS deploy — gnet.golia.jp on t01

This directory holds **pre-authored** request bodies for registering the `gnet` project on `devops.golia.jp` and bringing up `gnet.golia.jp` as a docker-compose deploy on t01. The agent does **not** invoke the devops API in autorun mode; the operator pastes these JSONs into curl with their `DEVOPS_API_KEY`.

Plan refs: §10.2 (SaaS topology), §17 step 11, `v1_1-deploy-target` memory. Devops API walkthrough: `~/workspace/goliajp/devops/wiki/deploy/register.md`. **Note** the wiki examples use `x-api-key:`, but the live server only honours `Authorization: Bearer dvps_...` — the docs are drifted; use the form below.

t01 runs every project as a docker-compose bundle under `/apps/<project>/`. The gnet SaaS bundle ships **at the repo root** (`docker-compose.yml` + `.env.example`) so the devops binary-deploy pipeline rsyncs the whole repo to `/apps/gnet/` and runs `docker compose up -d` from there.

## Pre-flight (do these BEFORE any devops call)

- [ ] Console builds clean: `cargo build --release -p gnet-console`.
- [ ] Local boot smoke: `cargo run -p gnet-console` with a fresh `.env.local`, hit `/health` → 200, `/ready` → 200 (needs PG reachable).
- [ ] Internal fleet has been on v1.1 for ≥ 1 week and the federation handshake has round-tripped (plan §15 pre-release checklist).
- [ ] OAuth credentials in hand (Google + GitHub + Apple per plan §6.2 if all three providers are enabled at launch). It's OK to deploy with all three blank — the binary just disables those providers and warns at startup.

## Six-step register

> All calls below need `Authorization: Bearer $DEVOPS_API_KEY`. Set the env var first; do **not** paste the key into any file in this repo.

```sh
export DEVOPS_API_KEY=$(cat ~/.config/devops/api-key)   # operator's local key
AUTH="-H Authorization:Bearer $DEVOPS_API_KEY"
```

### 1. Create project (idempotent — skip if 200 already)

```sh
curl -X POST https://devops.golia.jp/api/projects \
  -H "Content-Type: application/json" $AUTH \
  --data @deploy/saas/project.json
```

### 2. Define services

```sh
curl -X PUT https://devops.golia.jp/api/projects/gnet \
  -H "Content-Type: application/json" $AUTH \
  --data @deploy/saas/services.json
```

`source_path: "./"` rsyncs the entire repo to `/apps/gnet/`; `artifact_path: /apps/gnet` is where docker-compose runs.

### 3. Add Caddy site (apex + wildcard, one block)

```sh
curl -X POST https://devops.golia.jp/api/caddy/sites \
  -H "Content-Type: application/json" $AUTH \
  --data @deploy/saas/caddy-site.json
```

The Caddy block reverse-proxies to `t01:6015`. The wildcard cert covering `gnet.golia.jp` + `*.gnet.golia.jp` is auto-acquired through Cloudflare DNS-01 (wired at Caddy's global level on t01).

### 4. Add DNS records (two A records, both proxied)

```sh
# apex
curl -X POST https://devops.golia.jp/api/dns/records \
  -H "Content-Type: application/json" $AUTH \
  --data @deploy/saas/dns-apex.json

# wildcard (per-network host namespace, plan §16.8)
curl -X POST https://devops.golia.jp/api/dns/records \
  -H "Content-Type: application/json" $AUTH \
  --data @deploy/saas/dns-wildcard.json
```

Idempotency: check first with `curl -s $AUTH https://devops.golia.jp/api/dns/records | jq '.[] | select(.name == "gnet.golia.jp")'`. If the row exists with the same content, skip.

### 5. Deploy Caddyfile to t01

```sh
curl -X POST https://devops.golia.jp/api/caddy/deploy/t01 $AUTH
```

Diff first if you want a preview:

```sh
curl -X POST https://devops.golia.jp/api/caddy/diff/t01 $AUTH
```

### 6. Drop `.env` on t01, then trigger the deploy

The deploy pipeline rsyncs `./` → `/apps/gnet/` and runs `docker compose up -d`. Compose auto-loads `/apps/gnet/.env` for secrets. The `.env` is NOT in the repo — it has to land on t01 before the first deploy:

```sh
# 6a. one-time: drop the .env with real secrets
cp .env.example /tmp/gnet-env && $EDITOR /tmp/gnet-env
ssh t01 'sudo mkdir -p /apps/gnet'
scp /tmp/gnet-env t01:/tmp/gnet-env
ssh t01 'sudo install -o root -g root -m 0600 /tmp/gnet-env /apps/gnet/.env && rm /tmp/gnet-env'
rm /tmp/gnet-env

# 6b. trigger the deploy via the devops API
curl -X POST https://devops.golia.jp/api/deploy \
  -H "Content-Type: application/json" $AUTH \
  -d '{"project": "gnet"}'
```

Watch the job:

```sh
curl -s $AUTH 'https://devops.golia.jp/api/deploy/jobs?project=gnet&limit=1' | jq
```

## Post-deploy verification

- [ ] `curl -sf https://gnet.golia.jp/health` → `200 OK`.
- [ ] `curl -sf https://gnet.golia.jp/ready` → `200 OK` (PG round-trip).
- [ ] `curl -sf https://gnet.golia.jp/api/host-role` → `{"role":"console", ...}`.
- [ ] Open `https://gnet.golia.jp/` in a browser — SPA loads, sign-in screen renders.
- [ ] `ssh t01 'docker ps --filter name=gnet-saas'` → three containers (`gnet-saas-postgres`, `gnet-saas-valkey`, `gnet-saas-console`), all `(healthy)`.
- [ ] Per-network host: from a logged-in browser, create a test network slug `test`, visit `https://test.gnet.golia.jp/` — should resolve through the wildcard DNS, present the same shell, scoped to that network.
- [ ] Move project status from `developing` → `operating` in ProjectStore once green.

## File index

| File | Purpose |
|---|---|
| `deploy/saas/project.json` | step 1 body — registers `gnet` in ProjectStore |
| `deploy/saas/services.json` | step 2 body — registers `gnet-console` as a docker service on t01 |
| `deploy/saas/caddy-site.json` | step 3 body — adds the Caddy site (apex + wildcard) |
| `deploy/saas/dns-apex.json` | step 4 body — `gnet.golia.jp` A record |
| `deploy/saas/dns-wildcard.json` | step 4 body — `*.gnet.golia.jp` A record |
| `docker-compose.yml` (repo root) | the SaaS deploy compose: `postgres` + `valkey` + `console` |
| `.env.example` (repo root) | env template; real values go in `/apps/gnet/.env` on t01, never committed |
