# syntax=docker/dockerfile:1.7
#
# gnet v1.1 unified container image.
#
# Image: goliakk/gnet  (Docker Hub) and ghcr.io/goliajp/gnet (GHCR).
# Built + pushed multi-arch (linux/amd64 + linux/arm64) by the release
# pipeline (.github/workflows/release.yml) on every `v*` tag push.
#
# All four binaries land in one image; the entrypoint dispatches by
# `GNET_ROLE` (env) or the first positional arg:
#
#   GNET_ROLE=daemon      docker run goliakk/gnet up /etc/gnet/main.conf
#   GNET_ROLE=dispatcher  docker run goliakk/gnet
#   GNET_ROLE=relay       docker run goliakk/gnet --listen 0.0.0.0:65433
#   GNET_ROLE=console     docker run goliakk/gnet
#
# or, equivalently, positional:
#
#   docker run goliakk/gnet daemon up /etc/gnet/main.conf
#   docker run goliakk/gnet dispatcher
#   docker run goliakk/gnet relay --listen 0.0.0.0:65433
#   docker run goliakk/gnet console
#
# Backward-compat with v1.0 images: when neither GNET_ROLE nor a known
# role keyword is supplied as $1, the entrypoint defaults to the
# daemon, so the old `docker run goliakk/gnet:1.0.0 up /etc/gnet/main.conf`
# invocation keeps working unchanged on 1.1.0+.
#
# Daemon-mode caveat: the daemon needs CAP_NET_ADMIN + /dev/net/tun
# to bring up its overlay interface:
#   --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun
# (or `--privileged`; the cap-add form is tighter). Dispatcher / relay
# / console don't need either.

# ── 1. SPA bundle ──────────────────────────────────────────────────
FROM oven/bun:1 AS spa-builder
WORKDIR /spa

COPY console/package.json console/bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

COPY console/ ./
RUN bun run build && test -f dist/index.html

# ── 2. Rust workspace build ────────────────────────────────────────
FROM rust:1.83-slim-bookworm AS rust-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# SPA bundle lands at the relative path the include_dir!() macros use
# ($CARGO_MANIFEST_DIR/../../console/dist).
COPY --from=spa-builder /spa/dist ./console/dist

# build.rs files include_str!() this stub HTML and write it into
# console/dist if the real SPA bundle is missing. In this image dist
# IS populated by stage 1, but cargo still needs the stub to compile
# the build scripts.
COPY console/dist-stub.html ./console/dist-stub.html

# Single cargo invocation builds all four binaries in one workspace
# pass — the dep graph + crate compilations are shared, so this is
# roughly the cost of one full build, not four. Cache mounts make
# incremental rebuilds fast; artefacts are copied OUT before the RUN
# ends so the layer keeps them.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release \
        -p gnet \
        -p gnet-discover \
        -p gnet-relay-server \
        -p gnet-console \
 && mkdir -p /artefacts \
 && cp target/release/gnet               /artefacts/gnet \
 && cp target/release/gnet-discover      /artefacts/gnet-discover \
 && cp target/release/gnet-relay-server  /artefacts/gnet-relay-server \
 && cp target/release/gnet-console       /artefacts/gnet-console

# ── 3. Runtime ─────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime deps:
#   - iproute2 : daemon shells out to `ip` for tun config
#   - curl     : daemon optional coord poll + healthchecks
#                in the control-plane images (/bin/sh is dash, no /dev/tcp)
#   - ca-certificates : rustls trust roots for outbound HTTPS
#   - tini     : PID 1 + signal forwarding so SIGTERM from `docker stop`
#                reaches the binary and a clean shutdown happens within
#                the compose grace period
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iproute2 curl ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /artefacts/gnet               /usr/local/bin/gnet
COPY --from=rust-builder /artefacts/gnet-discover      /usr/local/bin/gnet-discover
COPY --from=rust-builder /artefacts/gnet-relay-server  /usr/local/bin/gnet-relay-server
COPY --from=rust-builder /artefacts/gnet-console       /usr/local/bin/gnet-console

# Persistent state for dispatcher's v1.0 importer + warm-standby
# fallback (no-op for the other roles).
RUN install -d -m 0750 /var/lib/gnet-discover

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Ports the control-plane roles bind by default. The daemon role uses
# network_mode: host (it shares the tun namespace), so its UDP port
# isn't EXPOSED here.
EXPOSE 65432/udp 8765/tcp 65433/udp 8766/tcp 6015/tcp

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD []
