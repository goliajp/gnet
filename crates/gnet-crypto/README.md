# gnet-crypto

Zero-dependency, pure-Rust cryptographic primitives for the **gnet** overlay
network — and usable standalone. Every primitive is implemented from the
specification and validated against its published **known-answer test
vectors**; nothing is pulled from crates.io.

> Part of a from-scratch WireGuard/Tailscale-class encrypted overlay. The
> guiding rule is **0 external dependencies, pure Rust** — we own the entire
> network path, crypto included.

## Primitives

| Module | Primitive | Spec | Notes |
|--------|-----------|------|-------|
| `chacha20` | ChaCha20 stream cipher | RFC 8439 §2 | constant-time by construction |
| `poly1305` | Poly1305 one-time MAC | RFC 8439 §2.5 | constant-time limb reduction (mask select) |
| `aead` | ChaCha20-Poly1305 AEAD | RFC 8439 §2.8 | constant-time tag compare on `open` |
| `x25519` | X25519 ECDH (Curve25519) | RFC 7748 | constant-time Montgomery ladder + masked cswap |
| `blake2s` | BLAKE2s hash + keyed MAC | RFC 7693 | configurable digest length, keyed mode |
| `hkdf` | HKDF over HMAC-BLAKE2s | RFC 5869 / 2104 | extract + expand |

## Design

- **No external crates.** `[dependencies]` is empty.
- **Constant-time on secret-dependent paths** (no data-dependent branches or
  table lookups in the cipher, MAC reduction, scalar multiply, or tag compare).
- **KAT-driven.** Each primitive is checked against its RFC/NIST vectors;
  HKDF (no standard BLAKE2s vector exists) is checked structurally plus by
  property tests over the KAT-verified hash.

## Example

```rust
use gnet_crypto::{aead, x25519};

// X25519 key agreement
let base = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};
let alice_sk = [0x11u8; 32];
let bob_sk = [0x22u8; 32];
let alice_pk = x25519::x25519(&alice_sk, &base);
let bob_pk = x25519::x25519(&bob_sk, &base);
let shared = x25519::x25519(&alice_sk, &bob_pk);
assert_eq!(shared, x25519::x25519(&bob_sk, &alice_pk));

// Authenticated encryption with the shared secret
let nonce = [0u8; 12];
let (ciphertext, tag) = aead::seal(&shared, &nonce, b"header", b"secret message");
let plaintext = aead::open(&shared, &nonce, b"header", &ciphertext, &tag).unwrap();
assert_eq!(plaintext, b"secret message".to_vec());
```

## Testing & benchmarks

```sh
cargo test  -p gnet-crypto   # RFC/NIST KATs + property tests
cargo bench -p gnet-crypto   # 0-dep throughput harness (no criterion)
```

Performance is currently the portable scalar reference; SIMD acceleration
(targeting parity with ring / RustCrypto / libsodium) is a tracked follow-up.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

© GOLIA K.K.
