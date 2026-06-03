# gnet self-host

Mode B: dispatcher + relay + Postgres + Valkey, no SaaS dependency. Brings up a complete v1.1 gnet control-plane on one host with `docker compose`.

> Mode B is the open-source baseline. If you want SaaS UX over your own self-hosted dispatcher, run this bundle and then register it with [gnet.golia.jp](https://gnet.golia.jp/) (Mode C — hybrid). If you just want SaaS, you don't need this — sign up at gnet.golia.jp.

## Requirements

- Docker 20.10+ with BuildKit (default in modern installs).
- Docker Compose v2 (`docker compose`, not legacy `docker-compose`).
- A reachable address daemons can hit. For LAN-only use, your host's LAN IP. For public use, your public IP + open UDP/TCP ports.

## Five-step init

### 1. Get the bundle

```sh
git clone https://github.com/goliajp/gnet.git
cd gnet/self-host
```

### 2. Set secrets

```sh
cp .env.example .env
$EDITOR .env
```

Fill in:
- `POSTGRES_PASSWORD` — any 20+ random characters (`openssl rand -base64 24`).
- `DISPATCHER_ADMIN_TOKEN` — at least 16 hex chars (`openssl rand -hex 24`).
- `RELAY_ADMIN_TOKEN` — same, fresh value.
- `RELAY_ADVERTISED_ENDPOINT` — the **address daemons see** for this relay, e.g. `192.168.1.10:65433` on a LAN, `<public-ip>:65433` on the internet.

Anything you don't override (ports, log level) takes the defaults from `.env.example`.

### 3. Build and start

```sh
docker compose up -d --build
```

First run builds three images (one each for dispatcher / relay / console-binary stages); subsequent runs reuse BuildKit's cache. The four services come up in dependency order — PG and Valkey become healthy first, the dispatcher waits for them.

### 4. Watch the boot

```sh
docker compose logs -f dispatcher
```

You should see:
- `running migrations` — dispatcher creates the v1.1 PG schema.
- `event=admin_up bind=0.0.0.0:8765` — admin server listening.
- `event=coord_up bind=0.0.0.0:65432` — v1.0 coord listener up (daemons join here).

The compose healthchecks tap `/api/host-role` on dispatcher (`:8765`) and relay (`:8766`) — `docker compose ps` should show both `healthy` within ~20 seconds.

### 5. Open the admin UI

```
http://<host>:8765/
```

The SPA loads, detects it's talking to a dispatcher, and shows the setup screen. You'll be prompted for a one-time setup token — the dispatcher prints it to the log on first boot:

```sh
docker compose logs dispatcher | grep -i 'setup token'
```

Use it to create the first local admin account (`owner` role). After that, log in with the username/password you just chose.

---

## Joining daemons

On any machine that should be a peer on this overlay:

```sh
gnet join --token <T> --coordinator http://<host>:65432
```

`<T>` is a per-device join token you generate in the dispatcher's admin UI under **Devices → Add device**. The daemon writes its conf, brings up the TUN interface, and registers with the coord — same flow as v1.0.

## Upgrading from v1.0

If you already have a v1.0 coord and want to move to v1.1 in place:

```sh
docker compose run --rm dispatcher \
    --import-state
```

Reads the legacy `state.json` mounted at `/var/lib/gnet-discover/state.json` and imports devices + relays into PG. The v1.0 daemons keep joining unchanged — the v1.0 coord wire is unchanged in v1.1.

## What's where

| Service | Port (host) | Purpose |
|---|---|---|
| `dispatcher` | `8765/tcp` | admin UI + JSON API + SPA (plan §5.2) |
| `dispatcher` | `65432/udp` | v1.0 coord listener (daemons join here) |
| `relay` | `8766/tcp` | relay admin (lite read-only, plan §5.3) |
| `relay` | `65433/udp` | RelayData forwarding (the actual relay) |
| `db` | — | postgres:18, dispatcher state (volume `pgdata`) |
| `kv` | — | valkey:9, session + federation cache (volume `kvdata`) |

PG and Valkey are not exposed on host ports — they only talk to the dispatcher over the compose-internal network. If you want direct PG access for ops:

```sh
docker compose exec db psql -U gnet gnet_dispatcher
```

## TLS

`docker compose up` serves plain HTTP on `:8765` (plan §11). If you want TLS, terminate it at a reverse proxy you front the dispatcher with — Caddy is the easy choice. Self-host does not bundle Caddy by design (out of scope).

## Tearing down

```sh
docker compose down               # stop containers, keep volumes
docker compose down -v            # also delete pgdata + kvdata + dispatcher-state
```

The second form is destructive — every device, audit row, and federation token is gone. Use it on a wrong-turn install; for normal shutdown the first form is what you want.
