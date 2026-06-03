# gnet

**An in-house, zero-dependency, post-quantum-ready encrypted overlay — Rust, WireGuard-class.**

`gnet` is a small UDP overlay stack written from scratch in pure Rust. The
data-plane crates (`gnet-crypto`, `gnet-noise`, `gnet-wire`, `gnet-relay`,
`gnet-punch`, `gnet-tun`, `gnet-rand`, `gnet-hex`, `gnet-config`) have **no
external crates.io dependencies**: every primitive is hand-written and
validated against its published RFC / NIST known-answer vectors.

## Status

Tagged `v1.0.0` (June 2026). The `gnet` daemon runs internally on a
small fleet (macOS arm64 + Linux x86_64 + AWS Graviton aarch64). The
post-1.0 roadmap (notably v1.1 — the SaaS control plane + console at
`gnet.golia.jp`) is in [ROADMAP.md](ROADMAP.md); shipping history is
in [CHANGELOG.md](CHANGELOG.md). Publishing the zero-dependency
library crates ("stones") to crates.io is a separate, deferred effort;
see [crates/PUBLISH.md](crates/PUBLISH.md) for the publish topology.

v1.0.0 includes the full operator surface (`gnet status` fused live
view, `gnet doctor` pre-flight verdict, `gnet metrics` Prometheus
exporter, admin unix-socket IPC), the quality-gate
([SECURITY.md](SECURITY.md), [KAT.md](crates/gnet-crypto/KAT.md),
[CT-REVIEW.md](crates/gnet-crypto/CT-REVIEW.md),
[fuzzing](docs/fuzzing.md)), and the deploy docs for every supported
posture. The toolchain policy is **always latest stable** — no version
pinning.

## What's in the box

| crate | role |
|---|---|
| **gnet-crypto** | ChaCha20-Poly1305, X25519, BLAKE2s, HKDF, SHA-3 / SHAKE, ML-KEM-768 — all hand-rolled, KAT-validated |
| **gnet-noise** | `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake (same pattern as WireGuard) |
| **gnet-wire** | UDP datagram framing (1-byte type tag, zero-alloc parse) |
| **gnet-relay** | Relay envelope framing (DERP-class fallback when direct path fails) |
| **gnet-relay-server** | Standalone relay daemon — single binary, no coordinator state, no plaintext awareness |
| **gnet-punch** | DCUtR-style synchronized hole-punch + symmetric-NAT port-prediction fan-out |
| **gnet-tun** | OS TUN device access (macOS utun + Linux `/dev/net/tun`), zero-dep FFI |
| **gnet-rand** | Cryptographically-secure RNG via OS entropy |
| **gnet-hex** | Lowercase-hex codec for keys on CLI / config |
| **gnet-config** | WireGuard-style multi-peer config parser (IPv4 + IPv6) |
| **gnet-discover** | Standalone control plane — JSON state + HTTP/1.1 API + token auth |
| **gnet** | The daemon — uplink (TUN → encrypt → UDP) + downlink (UDP → decrypt → TUN) |
| **gnet-bench-compare** | Cross-ecosystem perf comparison (vs RustCrypto / dalek / snow / libsodium / Go stdlib) — internal, not published |

## Why

* The control-plane and data-plane stay separable: `gnet` the daemon needs
  only path crates from this workspace, so a deployment can vendor exactly
  what it uses without pulling a 200-crate dep tree.
* Every hot-path primitive has measured numbers next to a SOTA Rust competitor
  (see `crates/gnet-bench-compare` and per-crate `BUDGETS.md` files) — the
  zero-dep policy is real only if the performance keeps up. As of v0.12 most
  primitives run **1.07–2.22× faster** than the RustCrypto baseline on both
  Apple Silicon and x86_64 AVX2 (ML-KEM decaps holds the largest margin).
* Post-quantum hybrid is part of the data-plane handshake, not a bolt-on:
  ML-KEM-768 keys ride alongside X25519 in the Noise IK pattern.

## Operating

Day-to-day CLI on a daemon-running host:

| command | when |
|---|---|
| `gnet status [--conf PATH]` | full picture — local conf, daemon liveness, runtime (reflexive endpoint, NAT verdict, relay health), and the coordinator roster with live session/path/last-handshake fused per peer |
| `gnet doctor [--conf PATH]` | green/red pre-flight: conf parse, key derive, coordinator reachability + pubkey recognition, admin socket, /etc/hosts splice, service unit. Exits non-zero on FAIL. |
| `gnet metrics` | Prometheus text from the daemon's admin socket; pipe to `/var/lib/node_exporter/textfile_collector/gnet.prom` for scraping |
| `gnet rotate-key [--conf PATH]` | mint a new identity, swap on coordinator + conf, atomic file replace |
| `gnet purge-hosts [--hosts PATH]` | remove the gnet-managed `/etc/hosts` block |

Deploy:

- **Linux + systemd:** [docs/deploy/linux-systemd.md](docs/deploy/linux-systemd.md)
- **Quality gate docs:** [SECURITY.md](SECURITY.md),
  [KAT.md](crates/gnet-crypto/KAT.md),
  [CT-REVIEW.md](crates/gnet-crypto/CT-REVIEW.md),
  [fuzzing.md](docs/fuzzing.md)

## License

Dual-licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
