# gnet-punch

Zero-dependency **DCUtR-style synchronized hole-punch rendezvous** for the
**gnet** overlay — the wire codec + the per-peer state machine.

> Part of a from-scratch WireGuard/Tailscale-class encrypted overlay. 0 external
> crates.io deps (only the sibling `gnet-wire` for the address codec).

## What it is

Two peers each behind their own NAT can't see each other's endpoint. They
exchange reflexive endpoints through a mutually-reachable **coordinator**, then
dial at the same instant — the origin after RTT/2, the target on receipt of the
sync — so their first packets cross at the path midpoint and each NAT sees the
peer's packet arrive on a mapping it just opened. This defeats the conntrack
tuple collision a naive simultaneous race hits.

This crate owns only the **bytes and the state transitions** — no sockets, no
peer table. The node binary drives it (relaying by destination key, then turning
a due dial into a handshake).

## Protocol

```text
PunchConnect body:  origin_pubkey(32) ‖ target_pubkey(32) ‖ reflexive-endpoint
PunchSync body:     origin_pubkey(32) ‖ target_pubkey(32)
```

connect: origin → coordinator → target (+ the target's reply the same way); the
origin times the round trip. sync: origin → coordinator → target; the origin
then waits RTT/2 while the target dials at once.

## State machine (`PunchState`)

```text
Idle ─start─▶ Connecting{sent_at} ─on_reply─▶ Syncing{dial_at,endpoint} ─due_dial─▶ handshake
Idle ─(target receives connect)─▶ Awaiting{endpoint} ─(dials on sync)─▶ handshake
```

- `on_reply(endpoint, now)` — origin: measure RTT from `sent_at`, schedule the
  dial at `now + RTT/2`, remember where to dial.
- `due_dial(now)` — the endpoint to dial once the deadline arrives.

## Design

- **0-dep** beyond `gnet-wire`; `#![forbid(unsafe_code)]`.
- Pure logic: clock injected via `now: Instant` params, so the state machine is
  unit-testable without sleeping.
- Hand-rolled std::time bench, `BUDGETS.md`, `tests/perf_gate.rs`, a randomized
  codec property test via the sibling `gnet-rand` (no proptest), plus
  README/CHANGELOG/dual-LICENSE/crates.io metadata.

## License

MIT OR Apache-2.0.
