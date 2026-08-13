-- Password-reset tokens (AAASM-5306, ADR 0031 §Q4, Epic AAASM-5301).
--
-- Postgres-gated, exactly like the other native-account tables (0008/0009): the
-- reset flow only exists on a Postgres-backed deployment. A reset token is a
-- single-use, expiring credential emailed to the account owner; only its
-- SHA-256 `token_hash` is stored — never the raw token (ADR 0031 security:
-- reset tokens hashed-at-rest, mirroring the invite/refresh token pattern).
--
-- Tenant-scoped like every other account table: `org_id` is stamped from the
-- user's verified org and the `tenant_isolation` RLS policy confines every row
-- to its tenant. An unset GUC sees zero rows (fail-closed).

-- password_reset_tokens: one row per issued reset request. `consumed_at` marks a
-- spent token; `expires_at` bounds its lifetime. A token is usable only while
-- both `consumed_at IS NULL` and `expires_at > now()` — the single-use gate is
-- enforced in the consuming UPDATE (see PgUserStore::consume_reset_token).
CREATE TABLE password_reset_tokens (
    id          UUID PRIMARY KEY,
    token_hash  TEXT NOT NULL,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL REFERENCES orgs(id),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A token is looked up by its hash at confirm time; unique so a hash collision
-- or a double-issue cannot produce two live tokens for the same hash.
CREATE UNIQUE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_org_id ON password_reset_tokens(org_id);

-- Row-Level Security: same DB-enforced tenant backstop as the other account
-- tables (0007/0008). FORCE RLS binds even the table owner, and the policy
-- denies any row whose `org_id` does not match the connection's `app.tenant_id`
-- GUC — an unset/empty GUC sees zero rows (fail-closed).
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON password_reset_tokens
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
