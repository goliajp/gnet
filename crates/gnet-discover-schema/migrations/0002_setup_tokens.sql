-- One-shot setup credentials. Used today for "first admin user on a fresh
-- dispatcher" (plan §17.2b); the schema is intentionally narrow to that
-- one purpose and will get a `purpose` column with a CHECK constraint
-- when a second use case lands.
--
-- Storage discipline matches plan §11: plaintext token leaves the binary
-- exactly once (printed on stdout for the operator) and never returns. We
-- store SHA-3-256 of the random 32 bytes that backed it.
--
-- TTL is enforced at the application layer (compare `expires_at` to
-- `now()`). The row itself stays around after consumption / expiry so
-- audit can answer "did this token ever get used"; a sweeper job for
-- ancient rows can be added later if it becomes worth the SQL.

CREATE TABLE setup_tokens (
    id          UUID         PRIMARY KEY,
    network_id  UUID         NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    -- 32-byte SHA-3-256 hash of the 32 random bytes that back the token.
    token_hash  BYTEA        NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    consumed_at TIMESTAMPTZ,
    UNIQUE (network_id, token_hash)
);

-- Hot path is "is there an outstanding unconsumed first-admin setup token
-- for this network", which the bootstrap step asks on every dispatcher
-- start. Partial index over the unconsumed-and-current set keeps it tight.
CREATE INDEX setup_tokens_active_idx
    ON setup_tokens (network_id)
    WHERE consumed_at IS NULL;
