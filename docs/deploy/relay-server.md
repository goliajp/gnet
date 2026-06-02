# Relay-server deploy — `gnet-relay-server`

`gnet-relay-server` is the standalone UDP relay: when two peers cannot
hole-punch a direct path (carrier-grade NAT, asymmetric firewall,
double NAT), they wrap their already-encrypted traffic in a
`Kind::RelayData` envelope and the relay forwards by destination
static key. The relay **never decrypts** — it sees only source /
destination X25519 public keys, no plaintext. Single binary, no
coordinator state, no persistent file.

This page walks through install and operate on Linux + systemd. The
unit file is at
[`crates/gnet-relay-server/deploy/gnet-relay-server.service`](../../crates/gnet-relay-server/deploy/gnet-relay-server.service).

## Prerequisites

- Linux with systemd (Debian 13 / kernel 6.12 is the reference build)
- A publicly reachable UDP port (default `65433`)
- A built `gnet-relay-server` binary
  (`cargo build --release -p gnet-relay-server`)
- The relay's `host:port` to advertise via the coordinator's
  `GNET_DISCOVER_RELAYS` environment variable (so daemons learn about
  it via `/peers`)

## Install

```bash
sudo install -m 0755 target/release/gnet-relay-server \
                                    /usr/local/bin/gnet-relay-server
sudo install -m 0644 crates/gnet-relay-server/deploy/gnet-relay-server.service \
                                    /etc/systemd/system/gnet-relay-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now gnet-relay-server
```

The unit binds `0.0.0.0:65433` by default. Override by editing the
`ExecStart` line:

```ini
ExecStart=/usr/local/bin/gnet-relay-server --listen 0.0.0.0:<port>
```

Then `systemctl daemon-reload && systemctl restart gnet-relay-server`.

## Advertise to the fleet

On the coordinator host, list this relay in
`/etc/gnet-discover/env`:

```bash
GNET_DISCOVER_RELAYS=relay1.example.com:65433
# or comma-separated for multiple relays
# GNET_DISCOVER_RELAYS=relay1.example.com:65433,relay2.example.com:65433
```

Then restart the coordinator. Daemons pick up the advertised relays on
their next `/peers` poll (≤ 30 s) and start using them for direct-path
fallback. The v0.20 health-probe loop pings each advertised relay
every keepalive interval; a stale relay is skipped in favour of a
healthier one (see `gnet metrics` →
`gnet_relay_health_age_ms{endpoint="…"}`).

## Verify

```bash
systemctl status gnet-relay-server
ss -ulpn | grep 65433           # UDP 65433 bound by the dynamic user
journalctl -u gnet-relay-server -n 20
```

The relay logs one summary line per minute with peer count + forwarded
packets/bytes:

```
gnet-relay-server: peers=5 forwarded=128 packets bytes_in=4.2MB bytes_out=4.2MB
```

`bytes_in` and `bytes_out` track equally (the relay never inflates or
deflates payload). Asymmetric numbers in journal mean a hot peer is
talking to a quiet one — still healthy.

## Stop / uninstall

```bash
sudo systemctl disable --now gnet-relay-server
sudo rm /etc/systemd/system/gnet-relay-server.service
sudo systemctl daemon-reload
```

The UDP socket is owned by the relay process; the kernel releases it on
process exit.

## Hardening

The unit runs under `DynamicUser=yes` — wider hardening profile than
the overlay daemon because the relay needs neither TUN nor
`CAP_NET_ADMIN`:

| Flag | Effect |
|---|---|
| `DynamicUser=yes` | dedicated transient user/group, no shell, no home |
| `ProtectSystem=strict` (no ReadWritePaths) | whole FS read-only — relay holds no on-disk state |
| `RestrictAddressFamilies=AF_INET AF_INET6` | UDP only |
| `MemoryMax=64M` + `LimitNOFILE=4096` | resource ceiling |
| `MemoryDenyWriteExecute=yes` | no `mmap(W+X)` — safe because the Rust binary doesn't JIT |
| `IPAccounting=yes` | per-instance IP byte counters (cloud-egress visibility) |

## Wire-format scope

The relay's wire is documented in
[`crates/gnet-relay-server/src/main.rs`](../../crates/gnet-relay-server/src/main.rs):
it honours only `Kind::RelayData (0x08)` and silently drops every other
datagram kind (init, msg2, transport, probe). This is intentional — a
relay that handled signaling would become a coordinator and break the
"never decrypts, never sees state" property.

Two consequences:

- **Punch signaling does not route through `gnet-relay-server`.** DCUtR
  rendezvous (`PunchConnect` / `PunchSync`) goes through a peer with
  `relay_eligible = true` (selected by `coordinator_endpoint` on the
  daemon side), not through a relay server.
- **Health probing uses self-addressed `RelayData`.** A daemon sends a
  `RelayData(src=self, dst=self)` envelope, which the relay records as
  a peer registration and then drops as self-addressed. The same path
  exchanges health pongs. This is also what the v0.21 metric
  `gnet_relay_health_age_ms` measures.

## Cloud-egress notes

On AWS:

- Outbound bytes from the relay = your inter-region or NAT-gateway
  egress cost. Watch `systemctl show gnet-relay-server -p
  IPEgressBytes` against billing.
- The default `MemoryMax=64M` comfortably handles a few hundred peers.
  Bump it if `forwarded` regularly hits high MB/s.
- Security group: open UDP `65433` (or your custom port) from the
  fleet's source range. The relay does not need ingress on any TCP
  port.

## Multi-relay

Daemons pick the freshest relay (lowest `health_age_ms`) on every
fallback decision. List multiple in
`GNET_DISCOVER_RELAYS` for redundancy and load distribution. There is
no central state — relays don't know about each other.
