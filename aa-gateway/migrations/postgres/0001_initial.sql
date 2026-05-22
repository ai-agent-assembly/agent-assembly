-- E18 S-C #2 — Initial PostgreSQL schema for the gateway storage backend.
--
-- All DDL uses IF NOT EXISTS so the file can be replayed safely against
-- an already-migrated database. sqlx::migrate! also tracks applied
-- versions in _sqlx_migrations, so this file would normally only run
-- once per database.
--
-- audit_events and metrics are plain tables here; E18 S-D upgrades them
-- to TimescaleDB hypertables via a follow-up migration.

-- ───────────────────────── Agent Registry ──────────────────────────────
CREATE TABLE IF NOT EXISTS agent_registry (
    agent_id         TEXT PRIMARY KEY,
    team_id          TEXT,
    org_id           TEXT,
    metadata         JSONB NOT NULL DEFAULT '{}',
    registered_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    enforcement_mode TEXT NOT NULL DEFAULT 'enforce'
);
CREATE INDEX IF NOT EXISTS idx_registry_team ON agent_registry(team_id);

-- ───────────────────────── Policy Versions ─────────────────────────────
CREATE TABLE IF NOT EXISTS policy_versions (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    version    INT NOT NULL,
    document   JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active  BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (name, version)
);

-- ───────────────────────── Audit Events ────────────────────────────────
-- E18 S-D will convert this table to a TimescaleDB hypertable on `ts`.
CREATE TABLE IF NOT EXISTS audit_events (
    ts              TIMESTAMPTZ NOT NULL,
    event_id        UUID NOT NULL,
    agent_id        TEXT NOT NULL,
    team_id         TEXT,
    action          TEXT NOT NULL,
    decision        TEXT NOT NULL,
    dry_run         BOOLEAN NOT NULL DEFAULT false,
    shadow_decision TEXT,
    matched_rule_id TEXT,
    payload         JSONB,
    PRIMARY KEY (ts, event_id)
);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id, ts DESC);

-- ───────────────────────── Metrics ─────────────────────────────────────
-- E18 S-D will convert this table to a TimescaleDB hypertable on `ts`.
CREATE TABLE IF NOT EXISTS metrics (
    ts       TIMESTAMPTZ NOT NULL,
    agent_id TEXT NOT NULL,
    metric   TEXT NOT NULL,
    value    DOUBLE PRECISION NOT NULL,
    labels   JSONB NOT NULL DEFAULT '{}'
);
