# `aasm`

<a id="cmd-aasm"></a>

aasm — command-line tool for Agent Assembly

## Synopsis

```text
Usage: aasm [OPTIONS] <COMMAND>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--context` | `<CONTEXT>` | Named context from ~/.aa/config.yaml to use |
| `--output` | `<OUTPUT>` (`table`, `json`, `yaml`) | Output format for list/get commands [default: table] |
| `--api-url` | `<API_URL>` | Override the API URL (takes precedence over context config) |
| `--api-key` | `<API_KEY>` | Override the API key (takes precedence over context config) |

## Subcommands

| Command | Description |
|---------|-------------|
| [`aasm admin`](aasm-admin.md#cmd-aasm-admin) | Gateway administrative operations |
| [`aasm agent`](aasm-agent.md#cmd-aasm-agent) | Manage monitored agent processes |
| [`aasm alerts`](aasm-alerts.md#cmd-aasm-alerts) | Manage governance alerts |
| [`aasm audit`](aasm-audit.md#cmd-aasm-audit) | Query audit log entries and export compliance reports |
| [`aasm logs`](aasm-logs.md#cmd-aasm-logs) | Query and stream audit log events |
| [`aasm policy`](aasm-policy.md#cmd-aasm-policy) | Manage governance policies |
| [`aasm context`](aasm-context.md#cmd-aasm-context) | Manage named API contexts (connection profiles) |
| [`aasm config`](aasm-config.md#cmd-aasm-config) | Validate an `agent-assembly.toml` runtime configuration file |
| [`aasm completion`](aasm-completion.md#cmd-aasm-completion) | Generate shell completion scripts |
| [`aasm docs`](aasm-docs.md#cmd-aasm-docs) | Generate documentation from the live CLI definition |
| [`aasm status`](aasm-status.md#cmd-aasm-status) | Show fleet health, agents, approvals, and budget at a glance |
| [`aasm version`](aasm-version.md#cmd-aasm-version) | Show CLI and gateway version information |
| [`aasm trace`](aasm-trace.md#cmd-aasm-trace) | Visualize a session trace (tree or timeline) |
| [`aasm approvals`](aasm-approvals.md#cmd-aasm-approvals) | Manage human-in-the-loop approval requests |
| [`aasm cost`](aasm-cost.md#cmd-aasm-cost) | Query cost summary and forecast spending |
| [`aasm dashboard`](aasm-dashboard.md#cmd-aasm-dashboard) | Open an interactive TUI dashboard for real-time governance monitoring |
| [`aasm gateway`](aasm-gateway.md#cmd-aasm-gateway) | Manage the aa-gateway governance daemon — agent registry, policy engine, audit log |
| [`aasm run`](aasm-run.md#cmd-aasm-run) | Launch an AI dev tool (claude, codex, copilot, windsurf) with governance wiring |
| [`aasm sandbox`](aasm-sandbox.md#cmd-aasm-sandbox) | Run a WebAssembly tool inside the Agent Assembly sandbox (filesystem + CPU + memory + wall-clock isolation) |
| [`aasm tools`](aasm-tools.md#cmd-aasm-tools) | List and manage AI dev tools on this system |
| [`aasm topology`](aasm-topology.md#cmd-aasm-topology) | Visualize agent topology, trees, lineage, and statistics |
| [`aasm proxy`](aasm-proxy.md#cmd-aasm-proxy) | Manage the aa-proxy sidecar — lifecycle, CA trust, and log tailing |
| [`aasm start`](aasm-start.md#cmd-aasm-start) | Start the locally-managed Agent Assembly gateway process |
| [`aasm stop`](aasm-stop.md#cmd-aasm-stop) | Stop the locally-managed Agent Assembly gateway process |

