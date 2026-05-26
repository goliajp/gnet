# gnet

A **secure UDP channel** over the in-house gnet stack — a working
demonstration that two endpoints can mutually authenticate and exchange
encrypted traffic with **zero external dependencies**.

Built on [`gnet-noise`](../gnet-noise) (Noise_IK handshake),
[`gnet-crypto`](../gnet-crypto) (the primitives) and
[`gnet-rand`](../gnet-rand) (OS entropy). The full path — OS entropy →
Noise_IK handshake → ChaCha20-Poly1305 transport → UDP — uses nothing from
crates.io.

## Usage

```sh
# generate a static keypair on each side
gnet keygen
#   private <64 hex>
#   public  <64 hex>

# responder (knows its own private key)
gnet listen 127.0.0.1:5555 <responder_private_hex>

# initiator (must know the responder's PUBLIC key — the Noise IK pattern)
gnet connect 127.0.0.1:5555 <initiator_private_hex> <responder_public_hex>
```

After the handshake, lines typed on the initiator's stdin are encrypted and
printed on the responder.

## Status

`listen`/`connect` carry application traffic over the encrypted channel
directly. OS network integration (a TUN device so `ping`/arbitrary IP
traffic flows through the gnet) is the next step.

The end-to-end handshake + transport is covered by an integration test
(`tests/secure_channel.rs`) that runs two endpoints over real UDP sockets.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

© GOLIA K.K.
