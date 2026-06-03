# syntax=docker/dockerfile:1.7
#
# gnet v1.1 self-host container bundle.
#
# Multi-stage build:
#   spa-builder  : bun → build the React SPA under console/dist
#   rust-builder : rust → cargo build --release for all 3 binaries,
#                  with the freshly-built SPA copied in so the
#                  include_dir!() embed picks up the real bundle
#   dispatcher / relay / console : minimal debian:slim runtimes,
#                                  one per target binary
#
# Build context is the repo root (the compose file under self-host/
# sets `context: ..` so `crates/` and `console/` are reachable).
#
# Selecting a binary: `--target dispatcher` / `--target relay` /
# `--target console`. The compose file does this per service.
#
# Cache: BuildKit cargo registry + target mounts make incremental
# rebuilds fast; SPA build deps cache via bun's lockfile-only first
# COPY.

# ── 1. SPA bundle ──────────────────────────────────────────────────
FROM oven/bun:1 AS spa-builder
WORKDIR /spa

# Cache the install layer on lockfile alone so source edits don't
# rebust the dep tree.
COPY console/package.json console/bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

COPY console/ ./
RUN bun run build && test -f dist/index.html

# ── 2. Rust workspace build ────────────────────────────────────────
FROM rust:1.83-slim-bookworm AS rust-builder

# C linker + headers for sqlx-rs / rustls compilation. `pkg-config`
# isn't strictly needed for our (rustls-tls) feature set but is
# cheap and prevents a future feature-add from surprising us.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Manifests first so the dep graph layer caches independently of
# source edits. The `crates/*/Cargo.toml` files are needed for
# workspace resolution; pull them in alongside the lockfile.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# SPA bundle from stage 1 lands at the same relative path the
# include_dir!() macros use ($CARGO_MANIFEST_DIR/../../console/dist).
COPY --from=spa-builder /spa/dist ./console/dist

# Single cargo invocation builds all three control-plane binaries
# in one workspace pass — the dep graph + crate compilations are
# shared, so this is roughly the cost of one full build, not three.
# Artefacts are copied OUT of the cache-mounted target dir before
# the RUN ends; the cache itself doesn't survive in the layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release \
        -p gnet-discover \
        -p gnet-relay-server \
        -p gnet-console \
 && mkdir -p /artefacts \
 && cp target/release/gnet-discover     /artefacts/dispatcher \
 && cp target/release/gnet-relay-server /artefacts/relay \
 && cp target/release/gnet-console      /artefacts/console

# ── 3a. dispatcher runtime ─────────────────────────────────────────
FROM debian:bookworm-slim AS dispatcher

# ca-certificates: rustls trust roots for outbound HTTPS (currently
# none from dispatcher, but cheap to ship); tini: PID 1 + signal
# forwarding so SIGTERM from `docker stop` reaches the binary and a
# clean shutdown happens within the compose grace period.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /artefacts/dispatcher /usr/local/bin/gnet-discover

# Persistent state for the v1.0 import path; PG is the source of
# truth in v1.1 but the importer + warm-standby still touch this
# file.
RUN install -d -m 0750 /var/lib/gnet-discover

EXPOSE 65432/udp 8765/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/gnet-discover"]

# ── 3b. relay runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim AS relay

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /artefacts/relay /usr/local/bin/gnet-relay-server

EXPOSE 65433/udp 8766/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/gnet-relay-server"]
CMD ["--listen", "0.0.0.0:65433"]

# ── 3c. console runtime ────────────────────────────────────────────
FROM debian:bookworm-slim AS console

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /artefacts/console /usr/local/bin/gnet-console

EXPOSE 6015/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/gnet-console"]
