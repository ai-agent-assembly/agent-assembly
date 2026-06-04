-- Audit logs: metadata-only governance records.
--
-- Per spec line 7551 ("don't store") this table holds NO payload, prompt, or
-- request body — only the metadata needed to answer "who did what, and what did
-- governance decide". There is deliberately no foreign key on `agent_id`: the
-- append-only sink must never fail because an agent row is absent or expired.
--
-- `event_id` is the idempotency key: a UUID derived from the event's content
-- hash. PRIMARY KEY makes it UNIQUE NOT NULL, so a retried publish collapses to
-- a single row (`INSERT … ON CONFLICT (event_id) DO NOTHING`) and the async
-- Gateway consumer never double-inserts.
CREATE TABLE audit_logs (
    event_id   UUID PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    tool_name  TEXT NOT NULL,
    decision   TEXT NOT NULL,
    latency_ms INT,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_agent_ts ON audit_logs(agent_id, ts DESC);
