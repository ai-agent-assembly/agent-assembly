-- AAASM-5288 — durable expiry for a time-limited (shadow) enforcement window.
--
-- ADR 0021 prerequisite: `enforcement_mode` is now round-tripped through the
-- registry storage bridge, but a shadow window also needs a deadline that
-- survives a restart. `enforcement_mode_expires_at` is NULL for the common
-- case (no deadline). When set, an already-expired window must resolve to the
-- base mode on rehydrate rather than being silently kept active — that rule is
-- enforced in `storage_bridge::storage_to_runtime`, not in SQL.
--
-- ADD COLUMN IF NOT EXISTS keeps this migration replay-safe.
ALTER TABLE agent_registry
    ADD COLUMN IF NOT EXISTS enforcement_mode_expires_at TIMESTAMPTZ;
