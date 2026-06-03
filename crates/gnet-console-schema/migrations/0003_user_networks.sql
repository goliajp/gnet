-- §17.6 console-side: user ↔ network ↔ dispatcher mapping.
--
-- One row per "network this user has federated with". The federation
-- token itself is NOT stored: we re-derive it on demand from
--   SHA3_256(master || user_id || network_label || dispatcher_endpoint)
-- so a leaked PG dump can't be replayed against a dispatcher. The
-- master comes from GNET_CONSOLE_FEDERATION_SECRET in env.
--
-- `mode` distinguishes SaaS-hosted dispatchers (provisioned by the
-- console at network-creation time) from self-host federations (the
-- user paste-registers their own dispatcher). v1.1 implements only
-- `self_host`; `saas` is reserved.

CREATE TABLE user_networks (
    id                  UUID         PRIMARY KEY,
    user_id             UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    network_label       TEXT         NOT NULL,
    mode                TEXT         NOT NULL CHECK (mode IN ('saas', 'self_host')),
    dispatcher_endpoint TEXT         NOT NULL,
    role                TEXT         NOT NULL DEFAULT 'owner',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (user_id, network_label)
);

CREATE INDEX user_networks_user_idx ON user_networks (user_id);
