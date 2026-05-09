-- Team-level approval routing configuration.
--
-- Each row maps a (team_id, approval_kind) pair to a set of approvers and
-- escalation settings. When approval_kind IS NULL the row acts as the
-- team-wide fallback: it matches any request for that team regardless of kind.
-- A row with a specific approval_kind overrides the fallback for that kind.

CREATE TABLE IF NOT EXISTS approval_routing_config (
    -- Team identifier matching AgentContext.team_id.
    team_id             TEXT    NOT NULL,
    -- Optional approval kind filter (e.g. 'tool_use', 'spawn').
    -- Empty string '' means "apply to all kinds for this team" (team-wide fallback).
    -- SQLite PRIMARY KEY does not treat NULLs as equal so we use '' as sentinel.
    approval_kind       TEXT    NOT NULL DEFAULT '',
    -- JSON array of approver identifiers (e.g. user IDs, role names).
    approvers           TEXT    NOT NULL DEFAULT '[]',
    -- Seconds to wait before escalating to escalation_approvers.
    escalation_timeout_secs INTEGER NOT NULL DEFAULT 300,
    -- JSON array of approver identifiers notified after escalation fires.
    escalation_approvers TEXT   NOT NULL DEFAULT '[]',

    PRIMARY KEY (team_id, approval_kind)
);
