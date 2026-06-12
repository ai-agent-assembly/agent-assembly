# Govern an agent end-to-end

**Goal.** Take a real AI dev tool on your machine — Claude Code, Codex, Copilot,
or Windsurf — and launch it so that everything it does runs through Agent
Assembly governance: it is registered with the gateway, tagged to a team and
trace, and routed through the proxy so its tool-calls and network requests are
policy-checked and audited.

## Prerequisites

- The `aasm` binary built (`cargo build -p aa-cli`; the binary is at
  `./target/debug/aasm`).
- The gateway binary on `PATH` for the `aasm start` helper
  (`cargo build -p aa-gateway --bin aa-gateway`).
- At least one supported AI dev tool installed.

## Step 1 — See which tools Agent Assembly can govern

`aasm` discovers the AI dev tools already installed on the system and reports the
**governance level** it can apply to each. This is a real probe of the machine,
not a static list:

```console
$ aasm tools list
+---------------+-----------------------+---------------------------------------------------------+------------------+
| TOOL          | VERSION               | PATH                                                    | GOVERNANCE LEVEL |
+====================================================================================================================+
| ClaudeCode    | 2.1.172 (Claude Code) | /opt/homebrew/bin/claude                                | L3Native         |
|---------------+-----------------------+---------------------------------------------------------+------------------|
| Codex         | codex-cli 0.135.0     | /opt/homebrew/bin/codex                                 | L2Enforce        |
|---------------+-----------------------+---------------------------------------------------------+------------------|
| GitHubCopilot | 1.388.0               | /Users/you/.vscode/extensions/github.copilot-1.388.0    | L1Observe        |
+---------------+-----------------------+---------------------------------------------------------+------------------+
```

The **governance level** reflects how deeply Agent Assembly can integrate with
that tool — from `L3Native` (the tool exposes a hook the runtime wires into
directly) down to `L1Observe` (the runtime can observe but not natively
intercept, so the proxy and eBPF layers do the enforcing).

## Step 2 — Start the gateway

The gateway is the decision engine every governed action is checked against.
For a local, in-process control plane:

```console
$ aasm start --mode local --port 7391
```

This serves the HTTP control-plane API and the dashboard on
`http://127.0.0.1:7391` with a local SQLite store. You can confirm it is up:

```console
$ aasm --api-url http://127.0.0.1:7391 status
Agent Assembly Status
─────────────────────────────────────
  Mode:      local
  Gateway:   http://127.0.0.1:7391
  Storage:   sqlite
  Version:   0.0.1-alpha.5
  Uptime:    2m 24s
  Health:    ✓ ok
─────────────────────────────────────

STORAGE
───────
  Backend:     sqlite
  Path:        /Users/you/.aasm/local.db
  DB Health:   ✓ ok  (0ms)
  Rows:        audit_events: 0 hot
               agents: 0  |  policies: 0
```

> The fleet starts empty (`agents: 0`) — nothing is governed until you launch a
> tool under `aasm run` in the next step.

## Step 3 — Launch the tool under governance

`aasm run <tool>` is the heart of this scenario. It assigns the session an
**agent identity**, a **team**, and a **trace id** for lineage tracking, wires
in the proxy, and then execs the real tool. Before running it for real, use
`--dry-run` to see exactly what governance wiring will be applied — nothing is
launched:

```console
$ aasm run claude --team-id research --agent-id research-bot-01 --dry-run
--- aasm run dry-run ---
agent_id:    research-bot-01
trace_id:    dry-run-daa9d73a-f2fc-4977-9d00-50f4c4025fa9
session_id:  dry-run-0d7a0c16-25b2-456b-84e8-b7907fa963d1

--- managed settings ---
<dry-run: managed settings not generated>

--- launch command ---
claude

--- environment ---
AA_AGENT_ID=research-bot-01
AA_REGISTRATION_ID=dry-run-2b00ef56-3f35-4ef9-8164-ea899dfe90aa
AA_SESSION_ID=dry-run-0d7a0c16-25b2-456b-84e8-b7907fa963d1
AA_TEAM_ID=research
AA_TRACE_ID=dry-run-daa9d73a-f2fc-4977-9d00-50f4c4025fa9
AI_AGENT=claude-code_2-1-165_agent
CLAUDECODE=1
CLICKUP_API_TOKEN=***MASKED***
GITHUB_TOKEN=***MASKED***
JIRA_API_TOKEN=***MASKED***
SLACK_BOT_TOKEN=***MASKED***
...
```

Notice two things that are doing real work:

- The `AA_*` environment variables (`AA_AGENT_ID`, `AA_TEAM_ID`, `AA_TRACE_ID`,
  `AA_REGISTRATION_ID`, `AA_SESSION_ID`) are injected so the launched tool's
  events carry identity and lineage back to the gateway.
- Secret-looking environment variables in your shell — API tokens, PATs — are
  **masked** (`***MASKED***`) in the launch environment that gets logged, so
  credentials never leak into the audit trail.

When you drop `--dry-run`, the same wiring is applied for real and the tool
starts. Useful flags:

| Flag | Effect |
|---|---|
| `--team-id <id>` | Tag the session to a team (drives team budgets and topology). |
| `--governance-level <level>` | Override the level Agent Assembly applies. |
| `--enforcement-mode observe` (or `--observe`) | Compute and audit policy decisions but never block — a shadow run. |
| `--enforcement-mode enforce` | Default — deny blocks, redact strips. |
| `--no-proxy` | Skip proxy injection (not recommended for governed environments). |
| `--root-agent <id>` | Record a parent for multi-agent lineage. |

The `--enforcement-mode` distinction matters when rolling governance out: start
with `--observe` to see what *would* be blocked without breaking the agent, then
switch to `enforce` once the policy is right.

## Step 4 — Observe the governed agent

Once the tool is running under `aasm run`, the registered agent appears in the
fleet and its actions flow into the audit log. You inspect it with:

```console
$ aasm agent list                 # all registered agents
$ aasm agent inspect <agent-id>   # one agent in detail
$ aasm topology team research     # the whole team
$ aasm status                     # fleet health at a glance
```

and watch its decisions live via the dashboard — see
[Observe in the dashboard](observe-in-dashboard.md).

## Result

You now have a real AI tool running with a stable governed identity, every
tool-call and outbound request routed through the gateway for an allow/deny
decision, secrets scrubbed from the recorded environment, and a complete audit
trail keyed to the agent, team, and trace you assigned in Step 3.
