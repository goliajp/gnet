-- Soft-delete column on user_networks (plan §6.3 / §15:
-- federation revocation must work in both directions).
--
-- When the user removes a network from their console view, we set
-- `removed_at = now()` instead of physically deleting the row. Two
-- reasons:
--
-- 1. The proxy route refuses to forward future requests for any
--    row with `removed_at IS NOT NULL`, so the on-dispatcher
--    federation token immediately stops working — no need for a
--    second round-trip to the dispatcher to revoke its trust row.
--    The operator can also revoke server-side (DELETE
--    /api/federation/{trust_id}); the two revocation paths are
--    independent and either alone is sufficient.
--
-- 2. The row survives in audit form. A re-registration with the
--    same (user_id, network_label) re-derives the same federation
--    token (the derivation is deterministic), so we want history.
--    UNIQUE (user_id, network_label) gets relaxed to ignore
--    removed rows so the user can re-add a name they previously
--    removed.

ALTER TABLE user_networks
    ADD COLUMN removed_at TIMESTAMPTZ;

-- Replace the strict UNIQUE with a partial UNIQUE that only sees
-- live rows. The original constraint had no name, so we drop by
-- column-derived name (PG's default for `UNIQUE (a, b)` on table
-- `t` is `t_a_b_key`).
ALTER TABLE user_networks
    DROP CONSTRAINT user_networks_user_id_network_label_key;

CREATE UNIQUE INDEX user_networks_user_label_live_idx
    ON user_networks (user_id, network_label)
    WHERE removed_at IS NULL;

-- Helpful for the proxy hot path which always filters live rows.
CREATE INDEX user_networks_user_live_idx
    ON user_networks (user_id)
    WHERE removed_at IS NULL;
