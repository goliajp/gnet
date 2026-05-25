# gnet-config

Zero-dependency parser for the **gnet** overlay's WireGuard-style node
configuration: a node's static identity plus a table of peers.

> Part of a from-scratch, 0-external-dependency overlay. Depends only on the
> sibling stones `gnet-hex` (key codec) and `gnet-crypto` (the `EK_LEN`
> constant).

## Format

One directive per line; `#` and blank lines are ignored.

```text
private <64-hex>            # our static private key
address <ip>               # our virtual (overlay) IP — the TUN address
listen  <bind_addr>        # UDP socket to bind, e.g. 0.0.0.0:7777
keepalive <secs>           # optional persistent-keepalive interval (0 disables)
peer <pubkey-64hex> <mlkem-ek-hex> <ip> [endpoint]
```

## API

- `parse(&str) -> Result<Config, String>` — parse the text form; the `Err`
  carries a `line N:` message.
- `Config` — `private`, `address`, `listen`, `keepalive`, `peers`.
- `PeerConfig` — `public`, `mlkem_ek`, `vip`, `endpoint`.

## Design

No external crates; `#![forbid(unsafe_code)]`. A cold-path parser run once at
node startup, so there is no per-packet budget — hence no bench/BUDGETS, in line
with the other utility stones. Randomized roundtrip coverage uses the sibling
`gnet-rand` (no proptest).

## License

MIT OR Apache-2.0.
