# Linux deploy — systemd

Two `gnet` daemons can run as systemd services: the per-host **overlay
daemon** (`gnet@<instance>`) that opens a `tun` device and talks to peers,
and the **relay daemon** (`gnet-relay-server`) that forwards
end-to-end-encrypted UDP for peers that can't punch directly. Each ships
with a unit file in `contrib/`:

- [`crates/gnet/contrib/systemd/gnet@.service`](../../crates/gnet/contrib/systemd/gnet@.service)
  — overlay daemon, template form
- [`crates/gnet-relay-server/deploy/gnet-relay-server.service`](../../crates/gnet-relay-server/deploy/gnet-relay-server.service)
  — relay daemon

This page walks through install, verify, and operate. The unit files
themselves carry the same install commands in their head comments — this
doc adds the context (config layout, hardening rationale, troubleshooting).

## Prerequisites

- Linux with systemd (Debian 13 / kernel 6.12 is the reference build)
- `iproute2` (`ip` command on `$PATH` — the daemon shells out for
  `ip addr add` / `ip link set`)
- `curl` (only when the conf carries a `coordinator` URL — the discovery
  thread uses curl for the HTTP poll)
- A built `gnet` binary (`cargo build --release -p gnet`) targeting the
  same arch as the host

## Overlay daemon — `gnet@<instance>`

### Install

```bash
sudo install -d -m 0755 /etc/gnet
sudo install -m 0600 main.conf                                /etc/gnet/main.conf
sudo install -m 0755 target/release/gnet                      /usr/local/bin/gnet
sudo install -m 0644 crates/gnet/contrib/systemd/gnet@.service /etc/systemd/system/gnet@.service
sudo systemctl daemon-reload
sudo systemctl enable --now gnet@main
```

The template unit's `%i` expands to the instance name, so
`gnet@main.service` loads `/etc/gnet/main.conf`, `gnet@home.service` loads
`/etc/gnet/home.conf`, etc. The unit's `ConditionPathExists=/etc/gnet/%i.conf`
means an instance with no conf file is a no-op rather than a crash loop.

### Verify

```bash
# Service state
systemctl status gnet@main
journalctl -u gnet@main -f         # follow log

# Interface
ip link show | grep tun            # tunN appears in UNKNOWN state
ip addr  show dev tun0             # overlay /24 is bound (or tun1, tun2, …
                                   # depending on what was already taken)

# Bandwidth (IPAccounting=true in the unit)
systemctl show gnet@main -p IPIngressBytes -p IPEgressBytes
```

A clean startup line looks like:

```
gnet[…]: node up on tunN (<overlay-v4>) with K peer(s)
```

If `K=0` for a static-conf instance, the conf has no `peer` lines and the
daemon will only listen.

### Stop / uninstall

```bash
sudo systemctl disable --now gnet@main
sudo rm /etc/systemd/system/gnet@.service /etc/gnet/main.conf
sudo systemctl daemon-reload
```

The `tun` interface is owned by the daemon's open fd (`IFF_TUN` without
`IFF_PERSIST`); the kernel destroys it the moment the process exits. No
PID file, no cleanup script — `systemctl stop` is enough.

### Hardening

The unit drops into a sandbox after start. Notable flags:

| Flag | Effect |
|---|---|
| `NoNewPrivileges=true` | Forbids `setuid`/`setcap` escalation |
| `ProtectSystem=strict` + `ReadWritePaths=/etc/gnet` | Whole FS read-only except `/etc/gnet` |
| `RuntimeDirectory=gnet` | systemd creates `/run/gnet/` on start (0755, root) and removes it on stop — used for the admin IPC socket `/run/gnet/admin.sock` (v0.21) |
| `ProtectKernelTunables`/`Modules`/`Logs` + `ProtectControlGroups` | No `/proc/sys` writes, no module ops, no cgroup mutation |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX` | Only the families the daemon actually uses (UDP, HTTP, ip-route, admin IPC) |
| `RestrictNamespaces=true` + `LockPersonality` + `RestrictRealtime` | No namespace/personality/realtime escalation |
| `MemoryDenyWriteExecute=true` | No `mmap(W+X)` — safe because the Rust binary doesn't JIT |
| `IPAccounting=true` | Per-instance IP byte counters via `systemctl show` |

`PrivateDevices` and `DynamicUser` are NOT used: the daemon needs
`/dev/net/tun` and `CAP_NET_ADMIN`. On Debian 13 + kernel 6.12 the unit's
`systemd-analyze security gnet@<i>` exposure score is **6.3 MEDIUM**,
which is the practical floor for a privileged TUN daemon — most of the
remaining surface (`IPAddressDeny`, `SystemCallFilter`) can't tighten
further without breaking the peer mesh.

### Conf shape

The static multi-peer config is documented in
[`crates/gnet-config/src/lib.rs`](../../crates/gnet-config/src/lib.rs).
Minimal viable:

```text
private  <64-hex>                  # from `gnet keygen`
address  10.42.0.1                 # overlay v4 — becomes tun's IP
listen   0.0.0.0:65432             # UDP bind
# coordinator http://discover.example:8443     # optional
# peer <pubkey-64> <mlkem-ek-hex> 10.42.0.2 1.2.3.4:65432
# alias    mini                    # optional: our coordinator alias; written by
#                                  # `gnet join`. Used for the self /etc/hosts entry.
# manage_hosts false               # optional: opt out of daemon /etc/hosts upkeep
#                                  # (default: on for coordinator-driven nodes)
# hosts_path /etc/hosts.d/gnet     # optional: splice target override (default /etc/hosts)
```

Modes:

- **Static**: list every peer line in the conf. Daemon ignores the
  coordinator path.
- **Coordinator-driven**: set `coordinator <url>` (and `device_token`
  if `/endpoint-report` is wanted). Discovery thread hot-adds peers via
  `GET /peers`. Initial registration is the one-shot `gnet join` command.

### Managed `/etc/hosts`

A coordinator-driven daemon keeps a marker-delimited block in `/etc/hosts`
in sync with the live peer set, so `ssh gnet-<alias>` resolves through the
overlay without a re-join:

```text
# ---BEGIN gnet---
10.42.42.2        gnet-t01
fd8d:f090:2ebb::2 gnet-t01
…
# ---END gnet---
```

`gnet join` writes this block once at onboard time; the daemon's discovery
loop **re-splices it on every peer-set change** (a peer joining, leaving, or
rotating keys). Only the block between the markers is touched — hand-edited
lines outside it are preserved. The write is atomic (tmp-file + rename) so the
system resolver never reads a half-written file. Names carry a `gnet-` prefix
so they never collide with Tailscale MagicDNS / mDNS.

Controls (conf directives above): `manage_hosts false` opts out entirely;
`hosts_path` redirects the splice (e.g. a dnsmasq sidecar include); `alias`
names this host's own self entry (absent → peer entries only). A purely
static node (no `coordinator`) never runs the discovery loop, so it never
auto-manages hosts — it keeps whatever `gnet join` wrote.

> **AWS / cloud-init gotcha.** Debian/Ubuntu cloud images ship
> `manage_etc_hosts: true`, which **rewrites `/etc/hosts` from a template on
> every boot** — wiping the gnet block until the next discovery poll re-adds
> it. Set it to `false` so the managed block survives a reboot:
>
> ```bash
> # /etc/cloud/cloud.cfg.d/99-gnet.cfg
> manage_etc_hosts: false
> ```
>
> The daemon would eventually re-splice on its next 30 s poll regardless, but
> disabling the rewrite avoids a post-boot window where `gnet-<alias>` names
> don't resolve.

## Relay daemon — `gnet-relay-server`

### Install

```bash
sudo install -m 0755 target/release/gnet-relay-server                     /usr/local/bin/gnet-relay-server
sudo install -m 0644 crates/gnet-relay-server/deploy/gnet-relay-server.service /etc/systemd/system/gnet-relay-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now gnet-relay-server
```

### Verify

```bash
systemctl status gnet-relay-server
ss -ulpn | grep 65433            # UDP 65433 bound
journalctl -u gnet-relay-server -n 20
```

Relay logs once a minute with peer count + forwarded packets/bytes.

### Hardening

The relay runs under `DynamicUser=yes` — systemd materialises a
transient user/group with no shell, no home, and reclaims them on stop.
Wider hardening profile than the overlay daemon (the relay needs neither
TUN nor `CAP_NET_ADMIN`):

- `MemoryMax=64M` and `LimitNOFILE=4096` for resource ceiling
- `IPAccounting=yes` for egress cost visibility

The relay's wire is documented in
[`crates/gnet-relay-server/src/main.rs`](../../crates/gnet-relay-server/src/main.rs):
it honours only `Kind::RelayData(0x08)` and never decrypts the inner.

## Log events

The daemon emits structured event lines on stderr (captured by
journald). Every operational event has a stable `event=<name>` tag plus
key=value fields, so simple grep / awk pipelines suffice — no JSON
parser, no logging framework.

| `event=` | Fires when | Fields |
|---|---|---|
| `node_up` | Daemon finished tun setup and entered the run loop | `tun`, `v4`, `v6`?, `peers` |
| `reflexive_discovered` | First time we learn our public `ip:port` from a probe reflection (or whenever it changes) | `endpoint` |
| `self_nat_detected` | Reflexive-vs-local-interface comparison settled | `is_nat`, `reflexive`, `reason` (`matches_local_if` \| `no_local_match`) |
| `peer_routed_via_relay` | Cold-start path selection picked the relay path for a peer | `peer`, `alias`, `relay`, `self_pub`, `peer_pub` |
| `peer_relay_fallback` | A peer's direct path failed enough times to fall back to relay | `peer`, `alias`, `punch_failures` |
| `direct_upgrade_succeeded` | A previously-relayed peer's direct upgrade completed (hole punch hit) | `vip`, `alias`, `endpoint` |
| `discovery_poll` | One coordinator `/peers` poll changed something | `added`, `updated`, `total` |
| `discovery_poll_failed` | The poll itself errored (curl exit, JSON parse, ...) | `error` |
| `endpoint_reported` | Successfully pushed our reflexive endpoint to `/endpoint-report` | `endpoint` |
| `endpoint_report_failed` | Endpoint-report POST errored | `error` |
| `peer_keys_rotated` | Discovery saw the same alias with a different pubkey — session reset | `alias` |
| `peer_adopted` | Static-conf peer (alias-less) got matched to a coordinator entry by overlay v4 | `vip`, `alias`, `pubkey_changed` |

Typical grep recipes:

```bash
# Count direct upgrade successes vs relay fallbacks for one instance.
journalctl -u gnet@main | grep -c event=direct_upgrade_succeeded
journalctl -u gnet@main | grep -c event=peer_relay_fallback

# Live-watch new peer events.
journalctl -u gnet@main -f | grep -E 'event=(peer_routed_via_relay|peer_adopted|peer_keys_rotated|direct_upgrade_succeeded)'

# Surface coordinator errors only.
journalctl -u gnet@main | grep -E 'event=(discovery_poll_failed|endpoint_report_failed)'
```

Free-form values (error messages) are quoted with `"…"`; everything
else is unquoted and shell-word-safe.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `gnet@<i>` immediately inactive after `start`, no journal line | `ConditionPathExists=/etc/gnet/%i.conf` failed — conf missing or wrong name |
| `gnet[..]: error: …` then exit 1 | Conf parse error or socket bind fail (e.g. UDP port already taken) |
| `node up` line appears but no `tun` interface | `CAP_NET_ADMIN` missing — check `NoNewPrivileges=true` interaction with the host's capability bounding set |
| Daemon up, no peers ever reach each other | If `coordinator` is set, check `journalctl … | grep discovery` for poll errors. If pure static, check that both ends list each other and have reachable `endpoint` fields. |
| `journalctl -u gnet@<i>` shows nothing | The unit log goes to the system journal by default — make sure `Storage=` in `/etc/systemd/journald.conf` is `auto` or `persistent` |

## Multi-instance

`gnet@home`, `gnet@work`, `gnet@mobile` can run side-by-side as long as
each conf binds a different UDP port and a different overlay subnet. The
template form makes this cheap — one unit file, N confs.
