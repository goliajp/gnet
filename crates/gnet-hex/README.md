# gnet-hex

Zero-dependency lowercase-hex encode/decode for the **gnet** overlay — keys on
the CLI and in config files.

> Part of a from-scratch, 0-external-dependency overlay. `[dependencies]` is
> empty.

## Install

```sh
cargo add gnet-hex
```

## Example

```rust
let key: [u8; 32] = [0xAB; 32];
let s = gnet_hex::encode(&key);
assert_eq!(s, "ab".repeat(32));
assert_eq!(gnet_hex::decode_32(&s), Some(key));
```

A runnable end-to-end demo lives at [`examples/roundtrip.rs`](examples/roundtrip.rs):

```sh
cargo run -p gnet-hex --example roundtrip
```

## API

- `encode(&[u8]) -> String` — lowercase hex.
- `decode(&str) -> Option<Vec<u8>>` — even-length, whitespace-trimmed; `None` if
  malformed.
- `decode_32(&str) -> Option<[u8; 32]>` — exactly 64 hex chars → 32 bytes.

`decode` / `decode_32` accept upper- or lower-case input (via `to_digit(16)`);
`encode` always emits lowercase.

## Design

No external crates; `#![forbid(unsafe_code)]`. Randomized roundtrip coverage uses
the sibling `gnet-rand` (no proptest). A cold-path utility (config parsing /
keygen output), so there is no per-packet budget — hence no bench/BUDGETS, in
line with the other utility stones.

## License

MIT OR Apache-2.0.
