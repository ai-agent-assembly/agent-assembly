-- DB-enforced tenant isolation (AAASM-3594): the core control of AAASM-3564.
--
-- Enable Row-Level Security and a `tenant_isolation` policy on every tenant-owned
-- table so the database itself rejects any row whose `org_id` does not match the
-- connection's verified tenant (`app.tenant_id`, set per checkout in 0595). This
-- sits below the ORM: "application code WILL someday forget a tenant_id filter —
-- the DB must be the backstop."
--
-- Design choices:
--   * FORCE ROW LEVEL SECURITY — applies the policy even to the table owner, so a
--     query run by the owning role is still tenant-confined (without FORCE, the
--     owner bypasses RLS).
--   * `NULLIF(current_setting('app.tenant_id', true), '')::uuid` — the `true`
--     (missing_ok) form yields NULL when the GUC is unset rather than raising,
--     and the `NULLIF(…, '')` collapses an empty-string residue (which a pooled
--     connection or a bare `SET app.tenant_id = ''` can leave) to NULL too, so
--     it never reaches the `::uuid` cast as `''`. `org_id = NULL` is never true,
--     so an unset OR empty connection sees ZERO rows: fail-closed, not
--     fail-open. This is what makes a forgotten `SET app.tenant_id` deny-all.
--   * WITH CHECK mirrors USING so a write cannot insert/relabel a row into
--     another tenant.
--
-- ROLE SPLIT (operational, not enforced here): the migration runner and any
-- admin/cross-tenant maintenance must use a role that is BYPASSRLS (or table
-- owner without FORCE-defeating privileges) — NOT the application row-access
-- role. FORCE RLS means even the table owner is policy-bound, so migrations and
-- backfills run as a privileged role; the runtime connection pool authenticates
-- as the unprivileged row-access role that IS subject to this policy. Mixing the
-- two would let the app role bypass isolation or block migrations.

ALTER TABLE agents      ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents      FORCE  ROW LEVEL SECURITY;
ALTER TABLE policies    ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies    FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_logs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs  FORCE  ROW LEVEL SECURITY;
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials FORCE  ROW LEVEL SECURITY;

-- agents.org_id is nullable (LifecycleStore::register carries no org context), so
-- its policy also admits the reserved system org for untagged liveness rows; a
-- NULL org_id row is still denied to every real tenant.
CREATE POLICY tenant_isolation ON agents
    USING (COALESCE(org_id, '00000000-0000-0000-0000-000000000000')
           = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (COALESCE(org_id, '00000000-0000-0000-0000-000000000000')
           = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON policies
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON audit_logs
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON credentials
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
