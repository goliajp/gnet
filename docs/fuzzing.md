# Fuzzing

Untrusted-input surfaces in the gnet stack have `cargo-fuzz` (libFuzzer)
harnesses. The harnesses live in `<crate>/fuzz/` subdirectories outside
the main workspace — they pull a nightly toolchain and dev-only crates.io
packages, neither of which should leak into the daemon's zero-deps build.

## What's wired up (v0.23 Track B)

| crate | target | what it fuzzes |
|---|---|---|
| `gnet-wire` | `wire_parse` | `parse`, `index`, `counter`, `decode_addr` — the first untrusted-input checks on every incoming UDP datagram. |
| `gnet-config` | `config_parse` | `parse(text)` — operator conf parser. A panic here is a deploy-time foot-gun. |
| `gnet-relay` | `relay_decode` | `decode`, `dst_key` — relay envelope decode that runs on every RelayData datagram on the relay server. |
| `gnet-noise` | `noise_read_message_1` | `HybridResponder::read_message_1` — the responder side reading an attacker-controlled hybrid Noise_IK msg1. |

## Prerequisites

- Nightly Rust toolchain (`rustup install nightly`).
- `cargo-fuzz` (`cargo install cargo-fuzz`).
- Linux or macOS; libFuzzer is bundled with rustc's LLVM.

## Running

Per target:

```bash
# from repo root
cd crates/gnet-wire && cargo +nightly fuzz run wire_parse
cd crates/gnet-config && cargo +nightly fuzz run config_parse
cd crates/gnet-relay && cargo +nightly fuzz run relay_decode
cd crates/gnet-noise && cargo +nightly fuzz run noise_read_message_1
```

A time-bounded smoke run (10 seconds) for CI-style triage:

```bash
cargo +nightly fuzz run <target> -- -max_total_time=10
```

A run that stops as soon as it hits a regression:

```bash
cargo +nightly fuzz run <target> -- -error_exitcode=1
```

Smoke results from v0.23 (10s per target, M2 / aarch64-apple-darwin):

| target | exec/s | exec total | finding |
|---|---|---|---|
| wire_parse | ~1.7M | 17M | none |
| relay_decode | ~1.7M | 17M | none |
| config_parse | ~330K | 3.4M | none |
| noise_read_message_1 | ~6K | 66K | none |

(The Noise harness is much slower because it rebuilds an ML-KEM keypair
per iteration. A `OnceLock`-cached responder would be ~100× faster but
hasn't been needed to find anything yet.)

## Corpora

`cargo-fuzz` keeps a corpus in `<crate>/fuzz/corpus/<target>/` —
gitignored. Seed corpora aren't checked in yet; the runner grows the
corpus organically from the random-byte start. If a future run finds
something worth holding onto, drop a minimised reproducer into
`<crate>/fuzz/artifacts/` and commit *that*, not the whole corpus.

## Adding a fuzz target

1. Pick an untrusted-input surface — a public `fn` that takes attacker-
   controlled bytes / text and shouldn't panic.
2. Decide which crate it lives in. Either add a new target to that
   crate's existing `fuzz/Cargo.toml` (`[[bin]]` stanza + a file in
   `fuzz_targets/`) or scaffold a fresh `fuzz/` directory if the crate
   doesn't have one (`cargo +nightly fuzz init` then rewrite the package
   name to `<crate>-fuzz` and add `[workspace]` to keep it outside the
   main workspace).
3. Build (`cargo +nightly fuzz build <target>`) and smoke-run for 10
   seconds before committing.
4. Add a row to the table above.

## Bugs found

None as of v0.23. This section is the future log — when a fuzz run
finds something, link the commit that fixed it.
