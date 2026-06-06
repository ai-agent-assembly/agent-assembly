# Command-Line Interface (`aasm`)

`aasm` is the operator front-end for an Agent Assembly deployment. It ships from
the [`aa-cli`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-cli)
crate and talks to the gateway over its HTTP API.

## Install

See the [README install section](https://github.com/AI-agent-assembly/agent-assembly#install-the-cli)
for the install script and Homebrew tap. For a local build:

```bash
cargo build -p aa-cli
./target/debug/aasm --help
```

## Global flags

These flags are available on every subcommand:

| Flag | Description |
|---|---|
| `--context <name>` | Named context (connection profile) from `~/.aa/config.yaml`. |
| `--api-url <url>` | Override the gateway API URL (takes precedence over the context). |
| `--api-key <key>` | Override the API key (takes precedence over the context). |
| `--output <fmt>` | Output format for `list`/`get` commands — `table` (default), `json`, … |

## Command groups

| Command | Purpose |
|---|---|
| `aasm status` | Fleet health, agents, approvals, and budget at a glance. |
| `aasm topology` | Visualize agent topology, trees, lineage, and statistics. |
| `aasm agent` | Manage monitored agent processes. |
| `aasm policy` | Manage governance policies. |
| `aasm alerts` | Manage governance alerts. |
| `aasm approvals` | Manage human-in-the-loop approval requests. |
| `aasm audit` | Query audit-log entries and export compliance reports. |
| `aasm logs` | Query and stream audit-log events. |
| `aasm trace` | Visualize a session trace (tree or timeline). |
| `aasm cost` | Query cost summary and forecast spending. |
| `aasm dashboard` | Open the interactive TUI dashboard (see [Dashboard](dashboard.md)). |
| `aasm gateway` | Manage the `aa-gateway` governance daemon. |
| `aasm proxy` | Manage the `aa-proxy` sidecar — lifecycle, CA trust, log tailing. |
| `aasm start` / `aasm stop` | Start / stop the locally-managed gateway process. |
| `aasm sandbox` | Run a WebAssembly tool inside the sandbox (fs / CPU / memory / wall-clock isolation). |
| `aasm config` | Validate an `agent-assembly.toml` runtime configuration file. |
| `aasm context` | Manage named API contexts (connection profiles). |
| `aasm completion` | Generate shell-completion scripts. |
| `aasm version` | Show CLI and gateway version information. |

> The `aasm run` and `aasm tools` dev-tool subcommands (launch and manage AI
> dev tools such as Claude Code, Codex, Copilot, and Windsurf with governance
> wiring) are present in the full build but stripped from the published crate.
> See [Dev-tool governance limits](https://github.com/AI-agent-assembly/agent-assembly/blob/master/docs/devtools/governance-limits.md).

## Examples

```bash
# Inspect the agent topology as JSON
aasm --output json topology overview

# Validate a runtime config file before boot
aasm config validate ./agent-assembly.toml

# Run the gateway against a bundled reference policy
cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml

# Open the live TUI dashboard against a named context
aasm --context staging dashboard
```

Every command supports `--help` for the full flag set, e.g. `aasm policy --help`.
