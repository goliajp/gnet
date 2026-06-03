-- Device kick (plan §17 step 7, second slice).
--
-- A kicked device stays in the table — its audit_log, snapshots and
-- vip allocations remain so we can answer "what was id=… called when
-- it last reported?" forever. The row is just marked `removed_at`.
--
-- That means the two natural unique keys (network_id, x25519_pubkey)
-- and (network_id, alias) must stop applying to kicked rows; otherwise
-- the same device can't re-register after a kick (and re-using a freed
-- alias would also fail). Drop the full-table UNIQUE constraints and
-- replace them with partial unique indexes scoped to the live rows.

ALTER TABLE devices ADD COLUMN removed_at TIMESTAMPTZ;

ALTER TABLE devices DROP CONSTRAINT devices_network_id_x25519_pubkey_key;
ALTER TABLE devices DROP CONSTRAINT devices_network_id_alias_key;

CREATE UNIQUE INDEX devices_active_pubkey_uniq
    ON devices (network_id, x25519_pubkey)
    WHERE removed_at IS NULL;

CREATE UNIQUE INDEX devices_active_alias_uniq
    ON devices (network_id, alias)
    WHERE removed_at IS NULL;

-- Lookups in the admin / internal paths filter on
-- `removed_at IS NULL`; give the planner a partial index to land on.
CREATE INDEX devices_active_network_idx
    ON devices (network_id)
    WHERE removed_at IS NULL;
