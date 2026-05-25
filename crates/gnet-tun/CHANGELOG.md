# Changelog

All notable changes to `gnet-tun` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate tracks the
workspace version.

## [Unreleased]

### Added

- Extracted from `gnetcli` into a standalone stone for the data plane: open and
  drive an OS TUN device with zero crates.io dependencies — FFI to the
  always-linked system C library (no `libc` crate) plus `std` for fd lifetime.
  Both macOS (`utun`) and Linux (`/dev/net/tun`, `IFF_TUN | IFF_NO_PI`) are
  implemented; each `unsafe` block carries a `// SAFETY:` note.
- README, dual LICENSE, crates.io metadata, and an `examples/open_tun.rs` for
  manual verification — opening a TUN device needs root, so it cannot run in
  unprivileged CI. A pure-I/O stone, so no bench/BUDGETS.

### Fixed

- macOS `send` now picks the 4-byte `utun` address-family header by IP version
  (`AF_INET6` = 30 for IPv6, `AF_INET` = 2 for IPv4) instead of hard-coding
  `AF_INET`. IPv6 overlay packets were leaving with an IPv4 family header and
  the kernel silently dropped them, so IPv6 overlay traffic never reached the
  TUN. Found by a real mac ↔ Linux IPv6 overlay ping; the Linux side
  (`IFF_NO_PI`) has no such header, so the netns IPv6 tests never caught it.
