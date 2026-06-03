-- Dispatcher baseline (v1.1). Mirrors `docs/v1.1-plan.md` §8.1.
--
-- Every table carries `network_id` because the same dispatcher binary
-- serves both single-network self-host (§1 Mode B) and multi-network
-- SaaS (§1 Mode A). The self-host case fixes a single networks row at
-- first-boot and re-uses its id everywhere; the SaaS case adds rows on
-- demand. No conditional code paths.
--
-- UUID PKs are application-generated; no pgcrypto / uuid-ossp required.
-- Timestamps are TIMESTAMPTZ; the daemon's RFC 3339 `created_at` strings
-- import directly.

CREATE TABLE networks (
    id                UUID         PRIMARY KEY,
    -- Human-facing label. For SaaS it's also the leftmost label of the
    -- per-network subdomain (§16.8: `<name>.gnet.golia.jp`), so the slug
    -- shape is enforced application-side (no spaces / uppercase / etc).
    name              TEXT         NOT NULL,
    -- Overlay prefix bytes, mirroring the daemon-side `Config` shape
    -- (`[u8; 3]` for v4, four big-endian `u16`s packed in 8 bytes for v6).
    -- Keeping it as BYTEA avoids round-tripping through INET / parsing
    -- when the dispatcher computes a new device's overlay address.
    overlay_v4_prefix BYTEA        NOT NULL,
    overlay_v6_prefix BYTEA        NOT NULL,
    settings          JSONB        NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE admin_users (
    id            UUID        PRIMARY KEY,
    network_id    UUID        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    username      TEXT        NOT NULL,
    -- argon2id hash; parameters live in a shared constant (see plan §11).
    password_hash TEXT        NOT NULL,
    -- Owner = original creator (one per network). Admin = additional
    -- operators added later. v1.1 only mints `owner`; `admin` exists
    -- for forward compat (the member-permission work is parked at 2.x).
    role          TEXT        NOT NULL CHECK (role IN ('owner', 'admin')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (network_id, username)
);

CREATE TABLE devices (
    id                UUID        PRIMARY KEY,
    network_id        UUID        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    -- Raw 32 bytes (NOT hex). The daemon's `state.json` stored hex; the
    -- v1.0→v1.1 importer (plan §12) decodes once on import.
    x25519_pubkey     BYTEA       NOT NULL,
    -- ML-KEM-768 encapsulation key, 1184 bytes raw.
    mlkem_ek          BYTEA       NOT NULL,
    alias             TEXT        NOT NULL,
    -- Overlay-side virtual IPs. INET is the right type — single addresses
    -- with optional masks — even though we store `/32` and `/128`.
    vip_v4            INET        NOT NULL,
    vip_v6            INET        NOT NULL,
    -- SHA-256 hash of the device_token issued at /join. The plaintext
    -- never enters PG (the daemon already holds the only copy on the
    -- node-side disk); the dispatcher hashes incoming tokens and
    -- constant-time compares against this column. Migration from v1.0
    -- (where state.json stored plaintext tokens) hashes on import.
    device_token_hash BYTEA       NOT NULL,
    relay_eligible    BOOLEAN     NOT NULL DEFAULT false,
    -- Last `host:port` the dispatcher observed via /endpoint-report.
    -- Text, not INET, because UDP endpoints carry a port and INET does
    -- not — and we never operate on it numerically.
    last_reflexive    TEXT,
    last_seen_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (network_id, x25519_pubkey),
    UNIQUE (network_id, alias)
);

CREATE INDEX devices_network_idx ON devices (network_id);

CREATE TABLE device_snapshots (
    id        BIGSERIAL   PRIMARY KEY,
    device_id UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    taken_at  TIMESTAMPTZ NOT NULL,
    -- The admin snapshot blob the daemon pushes (plan §17 step 4 lands
    -- the push channel; this table is the persistence target). Schema
    -- of `snapshot` is daemon-defined and evolves independently.
    snapshot  JSONB       NOT NULL
);

CREATE INDEX device_snapshots_device_taken_idx
    ON device_snapshots (device_id, taken_at DESC);

CREATE TABLE relays (
    id            UUID        PRIMARY KEY,
    network_id    UUID        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    -- "host:port". Same rationale as devices.last_reflexive — text wins
    -- because we need the port.
    endpoint      TEXT        NOT NULL,
    -- Probe state. 'unknown' | 'healthy' | 'unhealthy' | 'unreachable'.
    -- Plan §17 step 7 wires the probe; v1.1-import-time = 'unknown'.
    health        TEXT        NOT NULL DEFAULT 'unknown',
    last_check_at TIMESTAMPTZ,
    UNIQUE (network_id, endpoint)
);

CREATE INDEX relays_network_idx ON relays (network_id);

CREATE TABLE federation_trust (
    id              UUID        PRIMARY KEY,
    network_id      UUID        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    -- e.g. https://gnet.golia.jp — the console origin we trust.
    console_origin  TEXT        NOT NULL,
    -- Ed25519 verifying key the console signs federation tokens with;
    -- 32 bytes raw.
    console_pubkey  BYTEA       NOT NULL,
    -- The console-side user this trust row represents — opaque UUID
    -- from the console; the dispatcher does not look it up anywhere,
    -- it's surfaced in audit only.
    granted_user_id UUID        NOT NULL,
    -- SHA-256 hash of the long-lived federation token bearer. Same
    -- never-store-plaintext discipline as devices.device_token_hash.
    token_hash      BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    UNIQUE (network_id, token_hash)
);

CREATE INDEX federation_trust_network_idx ON federation_trust (network_id);

CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    network_id  UUID        NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 'local_admin' | 'federation' | 'system'.
    actor_kind  TEXT        NOT NULL,
    -- admin_users.id, federation_trust.id, or 'system' — stored as TEXT
    -- so we don't need polymorphic FKs.
    actor_id    TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    target      TEXT,
    detail      JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_log_network_time_idx
    ON audit_log (network_id, occurred_at DESC);
