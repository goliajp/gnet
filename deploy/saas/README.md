# gnet SaaS deploy — gnet.golia.jp on t01

This directory holds **pre-authored** request bodies + systemd unit + env template for registering the `gnet` project on `devops.golia.jp` and bringing up `gnet.golia.jp` as a binary deploy on `t01`. The agent does **not** invoke the devops API; the operator pastes these JSONs into curl with their `DEVOPS_API_KEY`.

Plan refs: §10.2 (SaaS topology), §17 step 11, `v1_1-deploy-target` memory. Devops API walkthrough: `~/workspace/goliajp/devops/wiki/deploy/register.md`.

## Pre-flight (do these BEFORE any devops call)

- [ ] Console builds clean: `cargo build --release -p gnet-console`.
- [ ] Local boot smoke: `cargo run -p gnet-console` with a fresh `.env.local`, hit `/health` → 200, `/ready` → 200 (needs PG reachable).
- [ ] Internal fleet has been on v1.1 for ≥ 1 week and the federation handshake has round-tripped (plan §15 pre-release checklist).
- [ ] t01 has PostgreSQL 18 + Valkey 9 running as systemd services. Verify: `ssh t01 systemctl is-active postgresql valkey`.
- [ ] Database + role created on t01:

  ```sql
  CREATE ROLE gnet_console WITH LOGIN PASSWORD '...';
  CREATE DATABASE gnet_console OWNER gnet_console;
  ```

- [ ] System user `gnet-console` exists on t01: `ssh t01 sudo useradd --system --no-create-home --shell /usr/sbin/nologin gnet-console` (idempotent — check first).
- [ ] OAuth credentials in hand (Google + GitHub + Apple per plan §6.2 if all three providers are enabled at launch).

## Six-step register

The wiki canonical is `~/workspace/goliajp/devops/wiki/deploy/register.md`. These files are the bodies for each call.

> All calls require `-H "x-api-key: $DEVOPS_API_KEY"`. Set the env var first; do **not** paste the key into any file in this repo.

### 1. Create project (idempotent — skip if 200 already)

```sh
curl -X POST https://devops.golia.jp/api/projects \
  -H "Content-Type: application/json" \
  -H "x-api-key: $DEVOPS_API_KEY" \
  --data @deploy/saas/project.json
```

### 2. Define services

```sh
curl -X PUT https://devops.golia.jp/api/projects/gnet \
  -H "Content-Type: application/json" \
  -H "x-api-key: $DEVOPS_API_KEY" \
  --data @deploy/saas/services.json
```

`source_path: "./"` means the deploy pipeline rsyncs the whole repo to `/apps/gnet-console/` and builds in place. That's `binary.md`'s "Build on device" mode and avoids cross-arch toolchain setup.

### 3. Add Caddy site (apex + wildcard, one block)

```sh
curl -X POST https://devops.golia.jp/api/caddy/sites \
  -H "Content-Type: application/json" \
  -H "x-api-key: $DEVOPS_API_KEY" \
  --data @deploy/saas/caddy-site.json
```

The block does `reverse_proxy {{resolve:t01:6015}}` — Caddy's templating resolves `t01:6015` to the local TCP address at deploy time (same convention as the existing `*.golia.jp` sites). The apex + wildcard share one site so the cert covers both; Caddy auto-acquires through Cloudflare DNS-01 (already wired at the Caddy global level on t01).

### 4. Add DNS records (two A records, both proxied)

```sh
# apex
curl -X POST https://devops.golia.jp/api/dns/records \
  -H "Content-Type: application/json" \
  -H "x-api-key: $DEVOPS_API_KEY" \
  --data @deploy/saas/dns-apex.json

# wildcard (every per-network host lives under this)
curl -X POST https://devops.golia.jp/api/dns/records \
  -H "Content-Type: application/json" \
  -H "x-api-key: $DEVOPS_API_KEY" \
  --data @deploy/saas/dns-wildcard.json
```

Idempotency: check first with `curl -s https://devops.golia.jp/api/dns/records | jq '.[] | select(.name == "gnet.golia.jp")'`. If the row exists with the same content, skip.

### 5. Deploy Caddyfile to t01

```sh
curl -X POST https://devops.golia.jp/api/caddy/deploy/t01 \
  -H "x-api-key: $DEVOPS_API_KEY"
```

Diff first if unsure:

```sh
curl -X POST https://devops.golia.jp/api/caddy/diff/t01 \
  -H "x-api-key: $DEVOPS_API_KEY"
```

### 6. Install systemd unit + drop .env.local, then deploy

The devops binary-deploy flow rsyncs `./` to `/apps/gnet-console/` and runs `systemctl restart gnet-console`. Before the first deploy, the systemd unit and the env file have to be in place on t01:

```sh
# 6a. copy the systemd unit (one-time)
scp deploy/saas/systemd/gnet-console.service t01:/tmp/
ssh t01 sudo install -o root -g root -m 0644 \
    /tmp/gnet-console.service /etc/systemd/system/gnet-console.service
ssh t01 sudo systemctl daemon-reload

# 6b. drop the env (one-time, with REAL secrets filled in from
#     the devops secret store — do NOT use the example values)
scp deploy/saas/.env.local.example t01:/tmp/gnet-console.env.local
# (edit /tmp/gnet-console.env.local with real values)
ssh t01 sudo install -o gnet-console -g gnet-console -m 0600 \
    /tmp/gnet-console.env.local /apps/gnet-console/.env.local
ssh t01 sudo chown -R gnet-console:gnet-console /apps/gnet-console

# 6c. trigger first deploy
curl -X POST https://devops.golia.jp/api/deploy \
  -H "Content-Type: application/json" \
  -H "x-api-key: $DEVOPS_API_KEY" \
  -d '{"project": "gnet"}'
```

Watch the job:

```sh
curl -s 'https://devops.golia.jp/api/deploy/jobs?project=gnet&limit=1' | jq
```

## Post-deploy verification

- [ ] `curl -sf https://gnet.golia.jp/health` → `200 OK`.
- [ ] `curl -sf https://gnet.golia.jp/ready` → `200 OK` (PG round-trip).
- [ ] `curl -sf https://gnet.golia.jp/api/host-role` → `{"role":"console", ...}`.
- [ ] Open `https://gnet.golia.jp/` in a browser — SPA loads, sign-in screen renders.
- [ ] Sign-in path: Google → OAuth round-trip → land on Networks tab.
- [ ] `ssh t01 systemctl status gnet-console` → `active (running)`, no recent restarts.
- [ ] `journalctl -u gnet-console --since "5 minutes ago"` → no panics, `listening` line present.
- [ ] Per-network host: from a logged-in browser, create a test network slug `test`, visit `https://test.gnet.golia.jp/` — should resolve through the wildcard DNS, present the same shell, scoped to that network.
- [ ] Move project status from `developing` → `operating` in ProjectStore once green.

## File index

| File | Purpose |
|---|---|
| `project.json` | Step 1 body — registers `gnet` in ProjectStore |
| `services.json` | Step 2 body — registers `gnet-console` service |
| `caddy-site.json` | Step 3 body — adds the Caddy site (apex + wildcard) |
| `dns-apex.json` | Step 4 body — `gnet.golia.jp` A record |
| `dns-wildcard.json` | Step 4 body — `*.gnet.golia.jp` A record |
| `systemd/gnet-console.service` | step 6a — systemd unit installed on t01 |
| `.env.local.example` | step 6b — env template; real values come from the devops secret store, never committed |
