-- Per-account failed-login lockout counter (AAASM-5305, ADR 0031 security).
--
-- Native login enforces a per-account lockout after N consecutive failed
-- attempts (→ HTTP 423 + retry-after). The counter MUST be durable, not in
-- memory (ADR 0031: "Counter is Postgres-backed, not in memory"), so a restart
-- or a multi-process deployment cannot reset an attacker's budget.
--
-- One row per account, keyed by user id. `failed_count` is the current run of
-- consecutive failures; a successful login resets it to zero. `locked_until`,
-- when in the future, is the wall-clock instant before which authentication is
-- refused regardless of correct credentials.
--
-- Tenant-scoped exactly like the other account tables (0008): `org_id` is
-- stamped from the user's verified org and the `tenant_isolation` RLS policy
-- confines every row to its tenant. An unset GUC sees zero rows (fail-closed).

CREATE TABLE login_attempts (
    user_id      UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    org_id       UUID NOT NULL REFERENCES orgs(id),
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_login_attempts_org_id ON login_attempts(org_id);

ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_attempts FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON login_attempts
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
