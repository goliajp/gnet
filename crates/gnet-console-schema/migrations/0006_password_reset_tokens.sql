-- Password-reset tokens (plan §6.6 follow-up).
--
-- Same shape + lifetime as email_verification_tokens (0005): 32 random
-- bytes hex-encoded, one-hour TTL enforced at lookup, single-use
-- (used_at = now() after consume). Kept in its own table so a stolen
-- verification-link can never be reused as a password-reset link and
-- vice-versa — the auth path the token unlocks is fixed by which
-- table it lives in.

CREATE TABLE password_reset_tokens (
    token        TEXT         PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    used_at      TIMESTAMPTZ
);

CREATE INDEX password_reset_tokens_user_idx
    ON password_reset_tokens (user_id)
    WHERE used_at IS NULL;
