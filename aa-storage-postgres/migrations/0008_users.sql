-- Native email/password accounts (AAASM-5304, ADR 0031, Epic AAASM-5301).
--
-- Postgres-gated: these tables exist only on a Postgres-backed deployment; the
-- in-memory mode stays API-key-only (ADR 0031 D2). Nothing here is wired into
-- request handling yet (that is AAASM-5305) — this is the durable data layer.
--
-- TENANT REFERENCE: the existing tenant boundary in this schema is `orgs.id`
-- (0001), and every tenant-owned table keys on an `org_id UUID REFERENCES
-- orgs(id)` column that Row-Level Security filters on (0006/0007). The ADR calls
-- this the user's `tenant_id`; the concrete column here is named `org_id` so it
-- matches the rest of the schema and plugs straight into the existing
-- `tenant_isolation` RLS policy and the `app.tenant_id` GUC seam.

-- Case-insensitive text, for a case-insensitive-unique email column. A contrib
-- extension shipped with the standard Postgres distribution (and the
-- postgres:18-alpine test image).
CREATE EXTENSION IF NOT EXISTS citext;

-- Role and status as Postgres enums. Values are lowercase to match the
-- `aa_auth::role::Role` / user status serde representations one-for-one.
CREATE TYPE user_role AS ENUM ('owner', 'admin', 'developer', 'viewer');
CREATE TYPE user_status AS ENUM ('active', 'invited', 'disabled');

-- users: a native human account. `password_hash` holds the argon2id PHC-encoded
-- string minted by `aa_auth::password::hash_password` — never plaintext. Email
-- is `citext` so uniqueness is case-insensitive.
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         CITEXT NOT NULL,
    password_hash TEXT NOT NULL,
    org_id        UUID NOT NULL REFERENCES orgs(id),
    role          user_role NOT NULL,
    status        user_status NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

-- Case-insensitive-unique email (citext folds case in the comparison).
CREATE UNIQUE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_org_id ON users(org_id);

-- user_invites: a single-use, expiring invitation to create an account. Only the
-- SHA-256 `token_hash` is stored — never the raw invite token (ADR 0031 security:
-- invite tokens hashed-at-rest). `consumed_at` marks a spent invite.
CREATE TABLE user_invites (
    id          UUID PRIMARY KEY,
    token_hash  TEXT NOT NULL,
    email       CITEXT NOT NULL,
    org_id      UUID NOT NULL REFERENCES orgs(id),
    role        user_role NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    invited_by  UUID REFERENCES users(id),
    consumed_at TIMESTAMPTZ
);

-- A token is looked up by its hash at accept time; unique so a hash collision or
-- a double-issue cannot produce two live invites for the same token.
CREATE UNIQUE INDEX idx_user_invites_token_hash ON user_invites(token_hash);
CREATE INDEX idx_user_invites_org_id ON user_invites(org_id);

-- refresh_tokens: an opaque, hashed-at-rest refresh token backing a revocable
-- session (ADR 0031 §5). Only the SHA-256 `token_hash` is stored. `revoked_at`
-- (logout / password change) and `expires_at` both invalidate a token.
--
-- `org_id` is denormalised from the owning user so the row sits under the same
-- `tenant_isolation` RLS policy as every other tenant-owned table; it is stamped
-- from the user's verified org at store time, never from client input.
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY,
    token_hash TEXT NOT NULL,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES orgs(id),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_org_id ON refresh_tokens(org_id);

-- Row-Level Security: extend the DB-enforced tenant backstop (0007) to the three
-- account tables. FORCE RLS binds even the table owner, and the policy denies any
-- row whose `org_id` does not match the connection's `app.tenant_id` GUC — an
-- unset/empty GUC sees zero rows (fail-closed), exactly like the existing tables.
ALTER TABLE users          ENABLE ROW LEVEL SECURITY;
ALTER TABLE users          FORCE  ROW LEVEL SECURITY;
ALTER TABLE user_invites   ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_invites   FORCE  ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON user_invites
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON refresh_tokens
    USING (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
