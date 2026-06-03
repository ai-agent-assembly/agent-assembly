-- Policies: versioned effective policy documents per agent.
--
-- The body is the serialized `PolicyDocument` (JSONB). Each (agent, version)
-- pair is unique; `get_policy` reads the highest `policy_version` for an agent,
-- which the descending composite index serves directly.
CREATE TABLE policies (
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    policy_version BIGINT NOT NULL,
    body           JSONB NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, policy_version)
);

CREATE INDEX idx_policies_agent_version ON policies(agent_id, policy_version DESC);
