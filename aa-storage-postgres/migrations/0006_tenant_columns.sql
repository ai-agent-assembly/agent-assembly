-- Tenant-discriminator columns (AAASM-3593): give `policies`, `audit_logs`, and
-- `credentials` the per-row `org_id` that Row-Level Security filters on.
--
-- Today only `agents` carries `org_id` (and nullably). The three child tables key
-- solely on `agent_id`/`key`, so the database has nothing to filter a tenant on
-- and RLS (0007) cannot be enforced. This migration adds that column to every
-- tenant-owned table and backfills it so the boundary is non-null going forward.
--
-- Tenant boundary is `orgs.id` (0001). Legacy rows that predate per-row tenant
-- tagging — and rows with no join path to an org — are assigned the reserved
-- system org below so the NOT NULL constraint can be made unconditional; RLS
-- then isolates them under a tenant no real customer is ever assigned.

-- Reserved system org for legacy/unassignable rows. The all-zeroes UUID is never
-- handed to a real tenant, so RLS confines these rows to a tenant that no caller
-- can set `app.tenant_id` to.
INSERT INTO orgs (id, name)
VALUES ('00000000-0000-0000-0000-000000000000', 'system (reserved)')
ON CONFLICT (id) DO NOTHING;

-- policies: backfill from the owning agent's org via the existing agent_id FK.
ALTER TABLE policies ADD COLUMN org_id UUID;
UPDATE policies p
   SET org_id = a.org_id
  FROM agents a
 WHERE p.agent_id = a.id
   AND a.org_id IS NOT NULL;
UPDATE policies SET org_id = '00000000-0000-0000-0000-000000000000' WHERE org_id IS NULL;
ALTER TABLE policies ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE policies ADD CONSTRAINT policies_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id);
-- Tenant-prefixed analogue of idx_policies_agent_version, so RLS-scoped reads of
-- the latest policy version stay index-served.
CREATE INDEX idx_policies_org_agent_version ON policies(org_id, agent_id, policy_version DESC);

-- audit_logs: agent_id is TEXT joinable to agents.id (no FK by design — the sink
-- must never fail on a missing agent). Backfill where the agent row exists.
ALTER TABLE audit_logs ADD COLUMN org_id UUID;
UPDATE audit_logs l
   SET org_id = a.org_id
  FROM agents a
 WHERE l.agent_id = a.id
   AND a.org_id IS NOT NULL;
UPDATE audit_logs SET org_id = '00000000-0000-0000-0000-000000000000' WHERE org_id IS NULL;
ALTER TABLE audit_logs ALTER COLUMN org_id SET NOT NULL;
-- No FK to orgs: keep audit append-only and fail-proof, matching the existing
-- no-FK-on-agent_id rationale (0004). Metadata-only invariant preserved — no
-- payload column added.
-- Tenant-prefixed analogue of idx_audit_logs_agent_ts.
CREATE INDEX idx_audit_logs_org_agent_ts ON audit_logs(org_id, agent_id, ts DESC);

-- credentials: no join path to an org (keyed only by `key`), so existing rows
-- get the reserved system org. New rows carry the writer's verified org.
ALTER TABLE credentials ADD COLUMN org_id UUID;
UPDATE credentials SET org_id = '00000000-0000-0000-0000-000000000000' WHERE org_id IS NULL;
ALTER TABLE credentials ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE credentials ADD CONSTRAINT credentials_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id);
CREATE INDEX idx_credentials_org_key ON credentials(org_id, key);
