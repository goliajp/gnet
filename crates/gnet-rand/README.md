# gnet-rand

Zero-dependency cryptographically-secure randomness from the operating
system, for the **gnet** overlay — and usable standalone. Reads
`/dev/urandom` via `std` only: **no `unsafe`, no crates.io dependencies.**

Used to generate Noise ephemeral and static private keys.

## Install

```sh
cargo add gnet-rand
```

## Platforms

Unix (Linux, macOS, the BSDs) via `/dev/urandom`. Windows support (via a CSP
syscall) is a future addition.

## Example

```rust
let sk = gnet_rand::random_32(); // 32 bytes for an X25519 private key
assert_ne!(sk, [0u8; 32]);

let mut nonce = [0u8; 12];
gnet_rand::fill(&mut nonce);
```

A runnable end-to-end demo lives at [`examples/random_32.rs`](examples/random_32.rs):

```sh
cargo run -p gnet-rand --example random_32
```

## API

- `try_fill(&mut [u8]) -> io::Result<()>` — fill a buffer, fallible.
- `fill(&mut [u8])` — fill a buffer, panicking if the OS RNG is unavailable.
- `random_32() -> [u8; 32]` — a fresh 32-byte secret.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

© GOLIA K.K.
