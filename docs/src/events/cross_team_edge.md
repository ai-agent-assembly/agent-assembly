# Event: `topology.cross_team_edge`

Published by `aa-gateway` whenever an edge is inserted between two agents
that belong to **different teams**.  Both agents must have a non-NULL `team_id`
in the agent registry; if either is missing the event is suppressed and an
`info`-level log line is emitted instead.

## Transport

Internal Tokio broadcast channel (`tokio::sync::broadcast::Sender<CrossTeamEdgeEvent>`).
Channel capacity: 64.  Slow consumers receive `RecvError::Lagged(n)` when they
fall behind.

Subscribers call `InMemoryEdgeRepo::subscribe_cross_team_events()`.

## Payload

Rust type: `aa_gateway::edges::CrossTeamEdgeEvent`

| Field | Type | Description |
|---|---|---|
| `edge_id` | `i64` | Auto-assigned id of the inserted edge |
| `source_agent_id` | `AgentId` (`[u8; 16]`) | Agent that originated the relationship |
| `source_team_id` | `String` | Team the source agent belongs to |
| `target_agent_id` | `AgentId` (`[u8; 16]`) | Agent that was the target |
| `target_team_id` | `String` | Team the target agent belongs to |
| `edge_type` | `EdgeType` | Semantic type: one of `delegates_to`, `calls`, `reads`, `writes`, `approves`, `messages` |
| `occurred_at` | `DateTime<Utc>` | UTC timestamp when the edge was recorded |

## Example (JSON-serialised for illustration)

```json
{
  "edge_id": 42,
  "source_agent_id": "01010101010101010101010101010101",
  "source_team_id": "team-alpha",
  "target_agent_id": "02020202020202020202020202020202",
  "target_team_id": "team-beta",
  "edge_type": "messages",
  "occurred_at": "2026-05-10T04:00:00Z"
}
```

## Publishing conditions

| Scenario | Action |
|---|---|
| `source.team_id != target.team_id` (both set) | Publish `CrossTeamEdgeEvent` |
| Either `team_id` is `NULL` | Log at `INFO`; no event |
| `source.team_id == target.team_id` | No event |

## Consumer notes (AAASM-198)

- Subscribe before inserting edges to avoid missing events on a lagged receiver.
- The broadcast channel drops events for receivers that fall more than 64 messages
  behind — design consumers to process promptly or buffer independently.
- `edge_id` can be used to fetch full edge metadata via `GET /api/v1/agents/{id}/edges`.
