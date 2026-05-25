# gnet-noise

The **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** handshake — the pattern WireGuard
is built on — with **no external dependencies**. It is implemented entirely on
the in-house [`gnet-crypto`](../gnet-crypto) primitives (X25519,
ChaCha20-Poly1305, BLAKE2s, HKDF); nothing comes from crates.io.

> Part of a from-scratch WireGuard/Tailscale-class encrypted overlay.

## What it does

`IK` lets an initiator that already knows the responder's static public key
establish a mutually-authenticated, forward-secret session in **one round
trip**:

```text
<- s                  (pre-message: responder static, known to the initiator)
...
-> e, es, s, ss       (message 1)
<- e, ee, se          (message 2)
```

After message 2 both sides `Split()` into a pair of transport ciphers
(one per direction).

## Design

- **No external crates.** Depends only on the in-house `gnet-crypto`.
- **Ephemerals are injected** by the caller — this crate contains **no RNG**,
  which keeps it deterministic-testable. Supplying fresh, secret ephemeral
  keys (e.g. from a future `gnet-rand`/OS entropy) is the caller's job.
- Modules: `cipher_state` (Noise §5.1), `symmetric_state` (§5.2),
  `handshake` (the IK initiator/responder state machines).

## Example

```rust
use gnet_noise::handshake::{Initiator, Responder};
use gnet_crypto::x25519;

let base = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};
let initiator_static = [0x11u8; 32];
let responder_static = [0x22u8; 32];
let responder_static_pub = x25519::x25519(&responder_static, &base);

// ephemerals injected by the caller (no RNG in this crate)
let mut initiator = Initiator::new(initiator_static, responder_static_pub, [0x33u8; 32]);
let mut responder = Responder::new(responder_static, [0x44u8; 32]);

let msg1 = initiator.write_message_1(b"hello");
responder.read_message_1(&msg1).unwrap();
let (msg2, mut responder_tp) = responder.write_message_2(b"world").unwrap();
let (mut initiator_tp, _payload) = initiator.read_message_2(&msg2).unwrap();

// bidirectional transport
let ct = initiator_tp.send.encrypt_with_ad(b"", b"ping");
assert_eq!(responder_tp.recv.decrypt_with_ad(b"", &ct).unwrap(), b"ping".to_vec());
```

## Testing

```sh
cargo test -p gnet-noise   # CipherState/SymmetricState units + full IK round-trip
```

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

© GOLIA K.K.
