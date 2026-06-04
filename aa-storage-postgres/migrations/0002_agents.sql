-- Agents: liveness bookkeeping keyed by the canonical agent id.
--
-- `id` is TEXT: the LifecycleStore contract identifies agents by an opaque
-- `AgentId`, persisted as its canonical hyphenated UUID string. `org_id` is
-- nullable because `LifecycleStore::register` carries no org context; the
-- foreign key is enforced only when an org is assigned out of band.
CREATE TABLE agents (
    id             TEXT PRIMARY KEY,
    org_id         UUID REFERENCES orgs(id),
    status         TEXT NOT NULL DEFAULT 'registered',
    registered_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat TIMESTAMPTZ
);

CREATE INDEX idx_agents_org_id ON agents(org_id);
