# gnet-tun

Zero-dependency OS **TUN device** access for the gnet overlay — the data-plane
hook that lets real IP traffic flow through the gnet. FFI to the always-linked
system C library (no `libc` crate, **no crates.io dependencies**); `unsafe` is
used for the device syscalls, each with a `// SAFETY:` note.

- **macOS** (`utun`) — implemented.
- **Linux** (`/dev/net/tun`) — planned.

## Install

```sh
cargo add gnet-tun
```

## Requires root

Opening a TUN device needs elevated privileges, so this crate cannot be
exercised in unprivileged CI. Verify manually:

```sh
sudo cargo run -p gnet-tun --example open_tun
# note the printed interface name (e.g. utun4), then in another terminal:
sudo ifconfig utun4 10.7.0.1 10.7.0.2 up
ping 10.7.0.2     # packets should print under the example
```

## API

- `Tun::open() -> io::Result<Tun>` — open the next free device.
- `tun.name()` — kernel-assigned interface name.
- `tun.recv(&mut [u8])` / `tun.send(&[u8])` — read/write IP packets (the
  4-byte address-family header is handled internally).

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

© GOLIA K.K.
