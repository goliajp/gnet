# gnet-wire

Zero-dependency, zero-allocation **datagram framing** for the **gnet** overlay
network.

> Part of a from-scratch WireGuard/Tailscale-class encrypted overlay. The
> guiding rule is **0 external dependencies, pure Rust**. `[dependencies]` is
> empty — only `std::net` is used.

## Install

```sh
cargo add gnet-wire
```

## Example

```rust
use gnet_wire::{Kind, frame, parse};
let dg = frame(Kind::HandshakeInit, b"msg1 bytes");
let (kind, body) = parse(&dg).unwrap();
assert_eq!(kind, Kind::HandshakeInit);
assert_eq!(body, b"msg1 bytes");
```

A runnable end-to-end demo lives at [`examples/frame_parse.rs`](examples/frame_parse.rs):

```sh
cargo run -p gnet-wire --example frame_parse
```

## What it is

Every datagram on the wire starts with a one-byte **type tag** so a node can
demultiplex handshake from transport from rendezvous traffic. Transport
datagrams carry a fixed header — `tag ‖ receiver-index(4) ‖ counter(8)` — before
the AEAD ciphertext, so a peer demuxes by session identity (not source address —
the basis for roaming) and the counter drives the AEAD nonce + anti-replay.

```text
transport:  tag(1) │ rx_index(4 LE) │ counter(8 LE) │ ciphertext‖aead-tag
            └────── TRANSPORT_HEADER = 13 ───────────┘
handshake:  tag(1) │ body…
```

## Tags

| Tag | Kind | Meaning |
|----:|------|---------|
| 0x01 | `HandshakeInit` | Noise_IK message 1 |
| 0x02 | `HandshakeResp` | Noise_IK message 2 |
| 0x03 | `Transport` | AEAD-protected payload |
| 0x04 | `EndpointProbe` | STUN-like reflexive-endpoint probe |
| 0x05 | `EndpointReply` | observed-source reply |
| 0x06 | `PunchConnect` | rendezvous connect (coordinator-relayed) |
| 0x07 | `PunchSync` | rendezvous synchronized-dial signal |

Tag values are a **protocol contract** — pinned by tests.

## API

- `Kind` / `Kind::from_byte` — the type tag.
- `frame(kind, body) -> Vec<u8>` — owned `tag ‖ body` (handshake, cold path).
- `parse(dg) -> Option<(Kind, &[u8])>` — split tag from body.
- `put_index` / `index` / `put_counter` / `counter` — transport-header field
  access, allocation-free: the ciphertext is built in place after
  `TRANSPORT_HEADER`.
- `encode_addr` / `decode_addr` — compact `SocketAddr` codec for endpoint
  discovery payloads.
- `HEADER` / `TRANSPORT_HEADER` — header sizes.

## Design

- **No external crates.** `[dependencies]` empty; only `std::net`.
- **Allocation-free transport path.** The tag occupies byte 0 of the same
  buffer the ciphertext is built in; `put_*` / readers touch fields in place.
  Only `frame` (handshake, rare) allocates.
- **`#![forbid(unsafe_code)]`** (where applicable).

See [`BUDGETS.md`](BUDGETS.md) for the latency baseline + the regression gate in
`tests/perf_gate.rs`.

## License

MIT OR Apache-2.0.
