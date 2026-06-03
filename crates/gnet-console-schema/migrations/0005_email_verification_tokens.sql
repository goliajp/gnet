-- Email-verification tokens (plan §6.6).
--
-- When `MAILRS_LOGIN_ADDRESS` + `MAILRS_LOGIN_PASSWORD` are set, the
-- console flips `auto_verify_email` off: a fresh signup lands in
-- `users` with `email_credentials.verified_at = NULL`, the register
-- handler INSERTs a row here, and dispatches a mail through mailrs
-- whose link points the user at `/verify?token=<hex>`. Clicking the
-- link calls `GET /api/auth/verify?token=…` which updates both
-- `verified_at` on the credential and `used_at` here in one tx.
--
-- Token shape: 32 random bytes hex-encoded (64 chars). The plaintext
-- only ever lives in the mail body + this row; it's not a session
-- credential — single-use, one-hour TTL enforced at lookup time.

CREATE TABLE email_verification_tokens (
    token        TEXT         PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    used_at      TIMESTAMPTZ
);

CREATE INDEX email_verification_tokens_user_idx
    ON email_verification_tokens (user_id)
    WHERE used_at IS NULL;
