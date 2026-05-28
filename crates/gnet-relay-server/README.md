# gnet-relay-server

Standalone relay daemon for the gnet overlay. **Single binary, two
dependencies** (`gnet-wire` + `gnet-relay`, both zero-dep themselves) —
nothing pulled from crates.io.

## What it does

Forwards `Kind::RelayData(0x08)` UDP datagrams between peers that can't
hole-punch a direct path (symmetric NAT, CGNAT, hairpin failures). The
relay never sees plaintext: the inner ciphertext stays end-to-end
encrypted, and the relay only reads the `dst_pubkey` field of the
[`gnet-relay`](../gnet-relay) envelope to look up where to forward.

```text
peer A  --RelayData(src=A, dst=B, inner=...)-->  relay  --(same datagram)-->  peer B
        ^                                                              ^
        e2e ciphertext, relay can't decrypt                            e2e ciphertext, only B can decrypt
```

## What it is NOT

- Not a coordinator. No peer registry from outside, no key distribution,
  no `gnet-discover` role.
- Not a full gnet daemon. No tun, no Noise handshake, no x25519 identity.
- Not a TURN server in the classic sense: no shared secret, no allocation
  protocol, no STUN over the same socket. Just a UDP forwarder keyed on
  the `dst_pubkey` of the gnet envelope.

## Peer registry

Trust-on-first-use, refreshed on every received envelope:

- When peer X sends a `RelayData` envelope to the relay, we store
  `(X's pubkey) -> (UDP endpoint we saw it from)` in a `HashMap`.
- When peer Y addresses an envelope `dst=X` at us, we look X up and
  forward to the stored endpoint.
- Entries idle for [`STALE_AFTER`](src/main.rs) (default 5 minutes) are
  pruned in-line on the recv path.

This is intentionally weaker than authenticated registration: a spoofed
`src` redirects future replies, but **cannot decrypt the session**
(everything past the routing header is end-to-end encrypted by the
gnet peers, with the relay not party to the handshake). The compromised
peer's next outbound refreshes the entry back automatically.

## Usage

```bash
# defaults: 0.0.0.0:51820, 5-minute idle prune
gnet-relay-server

# custom listen / idle
gnet-relay-server --listen 0.0.0.0:51820 --idle-secs 300
```

One UDP socket, single-threaded `recv_from` loop. No threads, no async
runtime, no allocation on the hot path.

## Operational

Sample systemd unit (`deploy/gnet-relay-server.service`):

```ini
[Unit]
Description=gnet overlay UDP relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/gnet-relay-server --listen 0.0.0.0:51820
Restart=on-failure
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
# AWS data egress visibility — `systemctl status` and the journal show
# ingress/egress per-unit. Cap externally via `IPAddressDeny=` if needed.
IPAccounting=yes

[Install]
WantedBy=multi-user.target
```

Egress accounting: with `IPAccounting=yes`, `systemctl show
gnet-relay-server` exposes `IPIngressBytes` / `IPEgressBytes`. Wire that
into Prometheus / a daily cron to monitor AWS data transfer cost.

## Build

Workspace member; same flags as everything else:

```bash
cargo build --release -p gnet-relay-server
```

Output: `target/release/gnet-relay-server` (a single statically-stripped
binary, ~1–2 MB depending on LTO).

## Tests

```bash
cargo test --release -p gnet-relay-server
```

CLI tests only — the forward loop is exercised by integration smoke tests
in the deployment, not the unit suite (a packet-forwarding test needs
two sockets + a third sender, which is real-network territory).
