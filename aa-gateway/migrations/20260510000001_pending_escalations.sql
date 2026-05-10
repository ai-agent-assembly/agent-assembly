-- Restart-safe pending escalation state for the DB-backed escalation scheduler.
-- Each row represents one approval request whose escalation timer is running.
-- Rows are deleted atomically inside a BEGIN IMMEDIATE transaction, which
-- serialises writer access and guarantees each row fires exactly once even
-- when multiple gateway instances share the same SQLite file.

CREATE TABLE IF NOT EXISTS pending_escalations (
    -- UUID of the in-flight approval request (TEXT, hyphenated form).
    approval_id     TEXT    NOT NULL PRIMARY KEY,
    -- Team identifier from the agent context.
    team_id         TEXT    NOT NULL,
    -- Role that will receive the escalated request.
    escalation_role TEXT    NOT NULL,
    -- Role from which escalation is happening (stored for the audit trail).
    from_role       TEXT    NOT NULL DEFAULT 'TeamAdmin',
    -- Unix epoch (seconds) at which escalation should fire.
    escalate_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_escalations_escalate_at
    ON pending_escalations (escalate_at);
