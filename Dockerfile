# Multi-stage build for the gnet overlay daemon.
#
# Image: goliakk/gnet
#
# The daemon needs CAP_NET_ADMIN + /dev/net/tun to bring up the overlay
# interface, so any `docker run` must pass:
#   --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun
# (or `--privileged`, but the cap-add form is tighter).
#
# Build context = repo root. Built + pushed to both Docker Hub
# (goliakk/gnet) and ghcr (ghcr.io/goliajp/gnet) by the release pipeline
# (.github/workflows/release.yml), multi-arch (linux/amd64 +
# linux/arm64), on every `v*` tag push.

# ── builder ──────────────────────────────────────────────────────
FROM rust:1.96-slim AS builder
WORKDIR /build

# Pull deps cache layer first by copying the manifests, then the full
# source. Speeds up rebuilds when only source changes.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --release -p gnet

# ── runtime ──────────────────────────────────────────────────────
FROM debian:13-slim

# gnet shells out to:
#   - `ip` / iproute2 for tun configuration
#   - `curl` for the optional coordinator poll
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/gnet /usr/local/bin/gnet

# Default to `gnet --help`; the operator passes `up /etc/gnet/main.conf`
# or other subcommands at `docker run` time.
ENTRYPOINT ["/usr/local/bin/gnet"]
CMD ["--help"]
