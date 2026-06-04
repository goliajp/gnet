-- Dispatcher → daemon control channel queue (plan §18.1 / v1.2-plan §5.2).
--
-- A row gets enqueued by an operator-facing write (rotate-key / restart /
-- upgrade in §18.A2-A3) and drained on the daemon's next admin-snapshot
-- push: the snapshot handler SELECTs `WHERE completed_at IS NULL AND
-- failed_at IS NULL`, attaches the rows to the 200 reply, and stamps
-- `delivered_at` so the same op is not delivered twice in a row even if
-- the daemon races two pushes. The daemon then POSTs to
-- /api/internal/snapshot/ack per op, flipping the row to
-- `completed_at` (success) or `failed_at` + `last_error` + attempts++
-- (failure; retries handled later by selecting rows where
-- `failed_at IS NULL OR attempts < N` — A1 keeps the simple "fail = done"
-- semantics so the queue can't loop forever before backoff lands).
--
-- `kick` stays in the CHECK enum for completeness, but the canonical
-- "daemon should stop existing" mechanism is still the `devices.removed_at`
-- soft-delete from migration 0003 — the snapshot push 401s once the row
-- is gone, no queue needed. Rotate-key / restart / upgrade do leave the
-- row alive and route through this table.

CREATE TABLE device_pending_ops (
    id            UUID PRIMARY KEY,
    network_id    UUID NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    device_id     UUID NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    op            TEXT NOT NULL CHECK (op IN ('kick','rotate_key','restart','upgrade')),
    args          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at  TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    failed_at     TIMESTAMPTZ,
    attempts      INT NOT NULL DEFAULT 0,
    last_error    TEXT
);

-- Drain path scans by device_id and only ever cares about un-finished rows;
-- a partial index keeps the scan cheap even after a long backlog of
-- completed/failed rows accumulates.
CREATE INDEX device_pending_ops_device_pending_idx
    ON device_pending_ops (device_id)
    WHERE completed_at IS NULL AND failed_at IS NULL;
