-- §17.5a console-side: split email/password credentials out of the
-- `users` table baseline. The plan (v1.1-plan.md §8.2) treats
-- email-with-password as one auth method among several (OAuth providers
-- being the others); modelling it as a sibling table avoids
-- nullable-everywhere on `users` and lines the schema up for the
-- per-OAuth-provider rows already present in `oauth_identities`.
--
-- `verified_at` records when the user clicked through the mailrs
-- verification link. v1.1 MVP defaults newly-created rows to verified
-- immediately when no SMTP transport is configured (so a self-host
-- install without mailrs still has a working sign-up); when mailrs is
-- configured the application leaves `verified_at` NULL until the link
-- is opened. The DB doesn't enforce either policy — that's a flag the
-- console binary reads from env.

CREATE TABLE email_credentials (
    user_id       UUID         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT         NOT NULL,
    verified_at   TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 0001 left a `password_hash` column on `users` as a forward-compat
-- stub; the live shape stores hashes in `email_credentials`. Drop it
-- before any data could land in it.
ALTER TABLE users DROP COLUMN password_hash;
