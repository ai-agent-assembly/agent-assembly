# Protocol Specification Changelog

> **Scope:** This changelog covers the Agent Assembly **protocol specification only** —
> proto message schemas, JSON schema, IPC framing contract, and SDK protocol conformance
> requirements. For runtime/crate release notes, see the project CHANGELOG when it exists.

All notable changes to the protocol specification are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Protocol versioning follows the policy in [docs/versioning.md](../versioning.md).

---

## [v0.0.1] — 2026-04-28

Initial release of the Agent Assembly protocol specification.

### Added

#### Services

- `AgentLifecycleService` (`proto/agent.proto`) — RPC surface for agent registration,
  heartbeat, deregistration, and runtime control stream
- `PolicyService` (`proto/policy.proto`) — synchronous policy check RPC for intercepting
  agent actions before execution
- `AuditService` (`proto/audit.proto`) — event reporting and streaming RPC for
  append-only, hash-chained audit log ingestion

#### Agent lifecycle messages (`proto/agent.proto`)

- `RegisterRequest` — agent startup registration carrying identity, framework, tool list,
  risk tier, public key, and arbitrary metadata
- `RegisterResponse` — gateway issues credential token, assigns policy, sets heartbeat
  interval
- `HeartbeatRequest` — periodic liveness signal carrying active run count and cumulative
  action count
- `HeartbeatResponse` — gateway signals policy update and/or suspend request to agent
- `DeregisterRequest` — clean or forced agent shutdown with optional reason string
- `DeregisterResponse` — gateway confirms deregistration success and echoes agent identity
- `ControlStreamRequest` — opens persistent server-streaming channel for runtime control
- `ControlCommand` — oneof wrapper dispatching to one of four command variants:
  - `SuspendCommand` — instructs agent to pause execution
  - `ResumeCommand` — instructs agent to resume execution
  - `PolicyUpdateCommand` — delivers updated policy document inline
  - `KillCommand` — instructs agent to terminate with optional reason

#### Policy messages (`proto/policy.proto`)

- `CheckActionRequest` — policy check request carrying agent identity, credential token,
  trace/span IDs, action type, and action-specific context
- `CheckActionResponse` — policy decision carrying `Decision` enum, reason, policy rule
  reference, optional approval ID, optional redact instructions, and decision latency
- `ActionContext` — oneof wrapper for the five action context subtypes:
  - `LLMCallContext` — model name, prompt token count, and sampled prompt prefix
  - `ToolCallContext` — tool name, source (mcp/builtin), JSON args, and target URL
  - `FileOpContext` — operation type, file path, and byte count
  - `NetworkCallContext` — method, URL, and header names
  - `ProcessExecContext` — executable path and argument list
- `RedactInstructions` — container for one or more redaction rules
- `RedactRule` — field path (JSONPath) and replacement string for a single redaction
- `BatchCheckRequest` — wraps multiple `CheckActionRequest` items for bulk evaluation
- `BatchCheckResponse` — wraps corresponding `CheckActionResponse` items

#### Event messages (`proto/event.proto`)

- `EnvelopedEvent` — typed event envelope with agent identity, timestamp, sequence number,
  and oneof payload for the five event subtypes
- `AlertTriggered` — credential or policy violation alert with severity and matched pattern
- `ApprovalRequested` — human-in-the-loop approval request with timeout and context summary
- `AgentStatusChanged` — agent lifecycle state transition notification
- `BudgetThresholdHit` — token or cost budget threshold breach notification
- `ApprovalDecision` — outcome of a previously requested approval

#### Audit messages (`proto/audit.proto`)

- `AuditEvent` — append-only, hash-chained audit record with agent identity, timestamp, sequence number,
  SHA-256 hash chain field, and oneof payload for five detail subtypes:
  - `LLMCallDetail` — model, token counts, finish reason
  - `ToolCallDetail` — tool name, source, args hash, result hash
  - `FileOpDetail` — operation, path, byte count, hash
  - `NetworkCallDetail` — method, URL, status code, response byte count
  - `ProcessExecDetail` — executable, args hash, exit code
- `PolicyViolation` — policy rule reference, decision, and triggering action summary
- `ApprovalEvent` — approval request and decision pair linked by approval ID
- `ReportEventsRequest` / `ReportEventsResponse` — unary bulk event submission
- `StreamEventsResponse` — server acknowledgement for the streaming submission RPC

#### Common types (`proto/common.proto`)

- `AgentId` — composite agent identity: `org_id`, `team_id`, `agent_id` (DID string)
- `Timestamp` — millisecond-precision Unix timestamp (`unix_ms` int64)
- `Decision` enum — `ALLOW`, `DENY`, `PENDING`, `REDACT`
- `ActionType` enum — `LLM_CALL`, `TOOL_CALL`, `FILE_OPERATION`, `NETWORK_CALL`,
  `PROCESS_EXEC`, `AGENT_SPAWN`
- `RiskTier` enum — `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

#### JSON Schema

- `schemas/policy/v1/policy-document.schema.json` — PolicyDocument JSON Schema v1,
  defining the structure of policy rules evaluated by `PolicyService`
- Example policy documents: `schemas/examples/strict.yaml`, `balanced.yaml`,
  `audit-only.yaml`

#### IPC framing contract

- Transport: Unix domain socket (`/var/run/aa-runtime.sock` by default)
- Framing: prost varint length-delimited encoding —
  each frame is a varint-encoded byte length followed by the raw proto bytes
- Reference: `prost::encode_length_delimited` / `prost::decode_length_delimited`
- Conformance vectors: `conformance/vectors/ipc_framing/` (10 vectors)

---

## Tagging runbook

Run the following commands **only when AAASM-12 (Protocol Specification epic) is fully
closed** and all protocol tickets have been merged into `master`:

```bash
# Create annotated tag for the initial spec release
git tag -a spec/v0.0.1 -m "Protocol Specification v0.0.1 — initial release"

# Push the tag to the upstream remote
git push origin spec/v0.0.1
```

Tag namespace convention: `spec/<version>` — coexists with future `runtime/<version>`,
`sdk/<version>` tags in the same monorepo without ambiguity.
