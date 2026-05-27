# gnet-relay

Zero-dependency, zero-allocation **relay envelope framing** for the **gnet**
overlay network — and usable standalone.

> Part of a from-scratch WireGuard/Tailscale-class encrypted overlay. The
> guiding rule is **0 external dependencies, pure Rust** — we own the entire
> network path. `[dependencies]` is empty.

## Install

```sh
cargo add gnet-relay
```

## What it is

When two peers cannot hole-punch a direct path (symmetric NAT, CGNAT, hairpin),
they fall back to relaying traffic through a mutually reachable node — the
DERP/TURN backstop every production overlay keeps. `gnet-relay` is the **wire
envelope** for that path and nothing else:

```text
 ┌──────────────┬──────────────┬───────────────────────────────┐
 │ src_pubkey   │ dst_pubkey   │ inner datagram (opaque)        │
 │ 32 bytes     │ 32 bytes     │ end-to-end-encrypted, verbatim │
 └──────────────┴──────────────┴───────────────────────────────┘
   HEADER_LEN = 64                runs to the end of the UDP payload
```

The relay reads **only** the 64-byte routing prefix to forward by destination
key. It never sees plaintext: the inner bytes are a complete, already-encrypted
datagram (the relay is not a handshake party for that session), so end-to-end
confidentiality holds even though the relay handles every packet.

## Why a separate crate

The overlay's stones-vs-cement split: this is a pure, zero-I/O **wire codec**
with no knowledge of peers, sockets, or sessions — exactly like the framing
layer. The node binary keeps the `by_pubkey → endpoint → send` forwarding glue
(which needs the live peer table); this crate owns only the bytes. That keeps
the crate independently testable, fuzzable, and benchmarkable.

## API

| Function | Path | Notes |
|----------|------|-------|
| `encode_into(out, src, dst, inner) -> Option<usize>` | hot | allocation-free; writes into a caller buffer |
| `decode(b) -> Option<(&src, &dst, &inner)>` | hot | borrows; inner may be empty |
| `dst_key(b) -> Option<&[u8;32]>` | hot | forward-only fast path — the only field a relay reads |
| `encode(src, dst, inner) -> Vec<u8>` | cold | owned convenience for tests / non-data-plane |

```rust
let src = [7u8; gnet_relay::KEY_LEN];
let dst = [9u8; gnet_relay::KEY_LEN];
let inner = b"...opaque end-to-end ciphertext...";

let mut buf = [0u8; 2048];
let n = gnet_relay::encode_into(&mut buf, &src, &dst, inner).unwrap();

// on the relay: route on dst only, forward the bytes unchanged
let target = gnet_relay::dst_key(&buf[..n]).unwrap();

// on the receiver: unwrap and re-dispatch the inner datagram
let (from, _to, payload) = gnet_relay::decode(&buf[..n]).unwrap();
```

A runnable end-to-end demo lives at [`examples/envelope_demo.rs`](examples/envelope_demo.rs):

```sh
cargo run -p gnet-relay --example envelope_demo
```

## Design

- **No external crates.** `[dependencies]` is empty; tests use the sibling
  `gnet-rand` for randomized coverage and benches use a hand-rolled `std::time`
  harness — no `criterion` / `proptest` / `libfuzzer-sys`.
- **Zero allocation on the hot path.** `encode_into` writes into the caller's
  send buffer; `decode` / `dst_key` borrow. Matches the per-packet discipline
  of `gnet-crypto`'s `seal_in_place`.
- **No length field.** The inner datagram is delimited by the UDP payload
  boundary, exactly as an unrelayed datagram is.
- **`#![forbid(unsafe_code)]`.**

See [`BUDGETS.md`](BUDGETS.md) for the throughput baseline and the regression
gate in `tests/perf_gate.rs`.

## License

MIT OR Apache-2.0.
