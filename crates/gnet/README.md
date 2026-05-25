# meshcli

A **secure UDP channel** over the in-house mesh stack — a working
demonstration that two endpoints can mutually authenticate and exchange
encrypted traffic with **zero external dependencies**.

Built on [`mesh-noise`](../mesh-noise) (Noise_IK handshake),
[`mesh-crypto`](../mesh-crypto) (the primitives) and
[`mesh-rand`](../mesh-rand) (OS entropy). The full path — OS entropy →
Noise_IK handshake → ChaCha20-Poly1305 transport → UDP — uses nothing from
crates.io.

## Usage

```sh
# generate a static keypair on each side
meshcli keygen
#   private <64 hex>
#   public  <64 hex>

# responder (knows its own private key)
meshcli listen 127.0.0.1:5555 <responder_private_hex>

# initiator (must know the responder's PUBLIC key — the Noise IK pattern)
meshcli connect 127.0.0.1:5555 <initiator_private_hex> <responder_public_hex>
```

After the handshake, lines typed on the initiator's stdin are encrypted and
printed on the responder.

## Status

`listen`/`connect` carry application traffic over the encrypted channel
directly. OS network integration (a TUN device so `ping`/arbitrary IP
traffic flows through the mesh) is the next step.

The end-to-end handshake + transport is covered by an integration test
(`tests/secure_channel.rs`) that runs two endpoints over real UDP sockets.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

© GOLIA K.K.
