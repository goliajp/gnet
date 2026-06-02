# Coordinator deploy — `gnet-discover`

`gnet-discover` is the control plane: it stores the device roster
(`state.json`), mints join tokens, answers `/peers` polls from daemons,
and (in warm-standby mode) mirrors a primary coordinator's state on an
interval so failover is a DNS / config swap rather than a fresh import.

This page walks through install, configure, verify, and operate on
Linux + systemd. The unit file is at
[`crates/gnet-discover/deploy/gnet-discover.service`](../../crates/gnet-discover/deploy/gnet-discover.service).

## Prerequisites

- Linux with systemd (Debian 13 / kernel 6.12 is the reference build)
- A reachable IP / DNS name the fleet's daemons will point their
  `coordinator` directive at
- A 16+ character admin token (operator-owned secret; used to mint
  device tokens, pull-sync between primary + standby, and authenticate
  the v0.21+ `/admin/*` endpoints)
- A built `gnet-discover` binary (`cargo build --release -p gnet-discover`)

## Install

```bash
# directory + state path (mode 0700, owned by the dynamic systemd user)
sudo install -d -m 0700 /etc/gnet-discover /var/lib/gnet-discover

# environment file — keep mode 0600 (carries the admin token)
sudo install -m 0600 gnet-discover.env       /etc/gnet-discover/env
sudo install -m 0755 target/release/gnet-discover  /usr/local/bin/gnet-discover
sudo install -m 0644 crates/gnet-discover/deploy/gnet-discover.service \
                                              /etc/systemd/system/gnet-discover.service
sudo systemctl daemon-reload
sudo systemctl enable --now gnet-discover
```

Minimal `/etc/gnet-discover/env`:

```bash
GNET_DISCOVER_BIND=0.0.0.0:65432
GNET_DISCOVER_STATE_PATH=/var/lib/gnet-discover/state.json
GNET_DISCOVER_ADMIN_TOKEN=<paste-32-char-secret>
# Optional: comma-separated relay-server endpoints
# GNET_DISCOVER_RELAYS=relay1.example:65433,relay2.example:65433
```

Warm-standby `/etc/gnet-discover/env` (on the backup host):

```bash
GNET_DISCOVER_BIND=0.0.0.0:65432
GNET_DISCOVER_STATE_PATH=/var/lib/gnet-discover/state.json
GNET_DISCOVER_ADMIN_TOKEN=<same-token-as-primary>
GNET_DISCOVER_PRIMARY=http://primary.example:65432
GNET_DISCOVER_SYNC_INTERVAL_SECS=10
```

A standby that has `GNET_DISCOVER_PRIMARY` set runs in **read-only**
mode: it serves `/peers` and `/healthz` from its mirrored state, but
rejects `/admin/*` and `/join` writes so a failover doesn't silently
fork the device table. Flip a standby to primary by removing the
`PRIMARY` line + restart.

## Verify

```bash
systemctl status gnet-discover
journalctl -u gnet-discover -f

# health check (no auth required)
curl -s http://localhost:65432/healthz

# admin status check (bearer auth)
curl -s -H "Authorization: Bearer $GNET_DISCOVER_ADMIN_TOKEN" \
     http://localhost:65432/admin/state | head -20
```

A clean startup line looks like:

```
gnet-discover: listening on 0.0.0.0:65432
```

A standby additionally logs:

```
gnet-discover: warm-standby, mirroring http://primary.example:65432 every 10s
```

## Validate a state.json backup

Before promoting a standby (or testing a recovery procedure), run the
`--validate-state` mode against the latest scp'd backup:

```bash
sudo -u gnet-discover gnet-discover --validate-state
```

It loads the configured `GNET_DISCOVER_STATE_PATH`, parses it against
the current `Device` schema, and exits 0 with the device count on
success, non-zero with a parse error on failure. Run this on the
warm-standby host periodically so a stale schema or corrupted file is
caught BEFORE the primary goes down.

## Operate

| Task | Command |
|---|---|
| Stop / off | `sudo systemctl disable --now gnet-discover` |
| Tail logs | `journalctl -u gnet-discover -f` |
| Backup state.json | `cp /var/lib/gnet-discover/state.json …` (file is atomically rewritten via tmp+rename — copying it always yields a consistent point-in-time) |
| Rotate admin token | edit `/etc/gnet-discover/env`, then `systemctl restart gnet-discover` (daemon tokens are unaffected — they're device-scoped, not admin-scoped) |
| Mint a join token | `curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:65432/admin/mint-token` |

## Hardening

The unit drops into systemd's sandbox profile (see the `.service` file
header comments). Notable:

| Flag | Effect |
|---|---|
| `DynamicUser=yes` | systemd materialises a transient user/group with no shell, no home, reclaimed on stop |
| `StateDirectory=gnet-discover` + `StateDirectoryMode=0700` | `/var/lib/gnet-discover` is owned by the dynamic user, only it can read state.json |
| `ProtectSystem=strict` + `ReadWritePaths=/var/lib/gnet-discover` | whole FS is read-only except the state directory |
| `RestrictAddressFamilies=AF_INET AF_INET6` | only the families the daemon uses (TCP) |
| `MemoryMax=128M` + `LimitNOFILE=4096` | resource ceiling |
| `IPAccounting=yes` | per-instance IP byte counters via `systemctl show` |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Daemon fails to start with `GNET_DISCOVER_ADMIN_TOKEN must be at least 16 chars` | the env file is missing the token or it's too short |
| Daemon fails to start with `Missing("GNET_DISCOVER_ADMIN_TOKEN")` | `EnvironmentFile=/etc/gnet-discover/env` not present or not readable |
| `state.json` ages don't tick | warm-standby mode without `GNET_DISCOVER_PRIMARY`, or the primary URL is wrong (check `event=state_sync_failed` in journal) |
| `/admin/state` returns 401 | wrong / missing bearer token, or you hit a standby (which rejects admin writes) |
| Daemons fall back to `/peers` polls with no body | coord process is up but state.json is empty — check `event=state_sync_persist_failed` or whether anyone ran `mint-token` + `join` yet |

## Multi-primary / region

A single coordinator is the v1.0 design. Multi-region geographic split
is post-1.0: see [ROADMAP.md](../../ROADMAP.md) (v1.1 control plane
+ console).
