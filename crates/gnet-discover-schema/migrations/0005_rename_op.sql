-- Add `rename` to the device_pending_ops op enum (v1.2-plan §18.A3.3).
--
-- SPA PUT /api/devices/{id}/alias keeps directly updating
-- `devices.alias` (so the UI sees the new name immediately) but now
-- ALSO enqueues a `rename` control-channel op whose args carry the
-- target alias; the daemon drains, swaps its conf, and restarts so
-- its local hosts splice + `/local/status` pick the new name up.
--
-- The reverse direction (daemon-side rename via `/local/alias`,
-- menubar/CLI) bypasses the queue and goes through the dedicated
-- /api/internal/alias/set internal endpoint instead — the daemon
-- already knows the target, so a queue entry would be a no-op.

ALTER TABLE device_pending_ops
    DROP CONSTRAINT device_pending_ops_op_check;

ALTER TABLE device_pending_ops
    ADD CONSTRAINT device_pending_ops_op_check
    CHECK (op IN ('kick','rotate_key','restart','upgrade','rename'));
