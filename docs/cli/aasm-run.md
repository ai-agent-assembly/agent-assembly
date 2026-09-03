# `aasm run`

<a id="cmd-aasm-run"></a>

Launch an AI dev tool (claude, codex, copilot, windsurf) with governance wiring

## Synopsis

```text
Usage: aasm run [OPTIONS] <TOOL> [TOOL_ARGS]...
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<TOOL>` | `<TOOL>` | The AI development tool to launch (claude, codex, copilot, windsurf) *(required)* |
| `<TOOL_ARGS>` | `<TOOL_ARGS>` | Arguments forwarded verbatim to the launched tool |
| `--agent-id` | `<AGENT_ID>` | Override the agent identity for this session |
| `--team-id` | `<TEAM_ID>` | Team identifier for this session |
| `--root-agent` | `<ROOT_AGENT>` | Root agent identifier for lineage tracking |
| `--governance-level` | `<GOVERNANCE_LEVEL>` | Override the governance level for this session |
| `--no-proxy` |  | Skip proxy injection (not recommended for governed environments) |
| `--dry-run` |  | Show the launch command and settings without executing |
| `--enforcement-mode` | `<ENFORCEMENT_MODE>` (`enforce`, `observe`, `disabled`) | Enforcement posture for this session — overrides the policy default for this agent. Defaults to `enforce` (live enforcement). When set to `observe`, policy decisions are recorded but never applied; the launched tool sees Allow for every action and shadow events land in the audit log |
| `--observe` |  | Shorthand for `--enforcement-mode observe`. Mutually exclusive with `--enforcement-mode` so the source of truth stays unambiguous |

