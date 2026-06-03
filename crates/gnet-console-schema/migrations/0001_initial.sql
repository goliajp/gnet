-- v1.1-B baseline. Only the auth-side tables (users + oauth_identities)
-- land here; networks + devices wait until 1.1-A push-channel pins their
-- on-the-wire shape (per ROADMAP), then arrive in a follow-up migration.
--
-- UUID PKs are application-generated (uuid::Uuid::new_v4()); no DB default,
-- no pgcrypto/uuid-ossp extension requirement.

CREATE TABLE users (
    id            UUID         PRIMARY KEY,
    -- Nullable: OAuth-only users may never set an email/password credential.
    email         TEXT         UNIQUE,
    -- Nullable: argon2id hash, NULL when the user authenticates via OAuth only.
    password_hash TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE oauth_identities (
    id               UUID        PRIMARY KEY,
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- CHECK constraint scopes the v1.1 provider set; widen by migration when
    -- another provider lands (don't bypass with raw inserts).
    provider         TEXT        NOT NULL CHECK (provider IN ('google', 'github', 'apple')),
    -- The provider's stable subject ID — what we look the User up by on each
    -- sign-in. Email can change, subject does not.
    provider_subject TEXT        NOT NULL,
    -- Snapshot of the email the provider gave us at link time; informational
    -- (display + audit), not used for lookup.
    email_snapshot   TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_subject)
);

CREATE INDEX oauth_identities_user_id_idx ON oauth_identities (user_id);
