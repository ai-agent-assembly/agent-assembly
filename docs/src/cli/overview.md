# CLI Reference — Overview

The `aasm` binary (crate `aa-cli`) is the operator front-end for Agent
Assembly. It talks to a running `aa-gateway` over its HTTP / OpenAPI surface
(default `http://localhost:8080`) for registry, policy, audit, approval, cost,
and topology operations, and manages local daemon processes (gateway, proxy,
dashboard) directly.

## Invocation

```text
aasm [OPTIONS] <COMMAND> [SUBCOMMAND] [ARGS]
```

Every command supports `--help` (`-h` for a one-line summary) at each layer:

```bash
aasm --help               # list all top-level commands
aasm policy --help        # list policy subcommands
aasm policy apply --help  # flags + arguments for one subcommand
```

## Global options

These flags are defined on the root parser (`aa-cli/src/lib.rs`) and are
**global** — they may be passed before the command or on any subcommand.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--context <CONTEXT>` | string | _(default context, if any)_ | Named context from `~/.aa/config.yaml` to use for the API URL and key. |
| `--output <OUTPUT>` | `table` \| `json` \| `yaml` | `table` | Output format for list/get commands. |
| `--api-url <API_URL>` | string | `http://localhost:8080` | Override the gateway API base URL. Takes precedence over the resolved context. |
| `--api-key <API_KEY>` | string | _(none)_ | Override the API key. Takes precedence over the context's stored key. |
| `-h, --help` | flag | — | Print help. |
| `-V, --version` | flag | — | Print the `aasm` version. |

> Several commands also expose a local `--output` or `--json` flag that
> overrides the global `--output` for that command only (e.g. `aasm logs
> --output json`, `aasm status --json`, `aasm gateway status --json`). These
> are called out on the relevant command pages.

## Output formats

`--output` (source: `aa-cli/src/output.rs`) selects how list/get commands
render:

- **`table`** (default) — human-readable, colorized tables via `comfy-table`.
- **`json`** — machine-readable pretty JSON.
- **`yaml`** — machine-readable YAML.

Commands that stream (`aasm logs --follow`, `aasm approvals watch`),
visualize (`aasm trace`, `aasm topology tree`), or open a TUI (`aasm
dashboard`) ignore `--output` where it does not apply.

## Config and context resolution

CLI configuration lives at **`~/.aa/config.yaml`** (source:
`aa-cli/src/config.rs`). It holds named contexts (connection profiles), an
optional default context, and dashboard settings:

```yaml
default_context: production
contexts:
  production:
    api_url: https://api.example.com
    api_key: prod-key
  staging:
    api_url: https://staging.example.com
dashboard:
  port: 3000
  auto_open: false
```

The active API URL and key are resolved with this precedence (highest first):

1. Explicit `--api-url` / `--api-key` flags.
2. The named context — `--context <name>`, otherwise `default_context`.
3. Built-in default URL `http://localhost:8080` (no key).

Manage contexts with the [`aasm context`](context.md) command group.

> **Note on paths.** The CLI *config* file is `~/.aa/config.yaml`. Separately,
> the locally-managed gateway uses `~/.aasm/` for its runtime artifacts —
> `~/.aasm/config.yaml` (gateway config, see [`aasm start`](start-stop.md)),
> `~/.aasm/policy.yaml`, `~/.aasm/logs/gateway.log`, and `~/.aasm/gateway.pid`.
> These are distinct files.

## Exit codes

`aasm` follows the standard convention:

- **`0`** — success.
- **non-zero** — failure. Common causes: the gateway is unreachable, the API
  returned a non-2xx status, a named context was not found, a file failed to
  parse, or a validation/simulation step found problems.

Some commands give the exit code a documented meaning so it can gate CI:

| Command | Non-zero exit means |
|---|---|
| [`aasm status`](status.md) | Gateway unreachable, any agent has violations, or storage health probe reports `unavailable`. |
| [`aasm policy simulate`](policy.md) | The simulation detected policy violations. |
| [`aasm policy validate`](policy.md), [`aasm config validate`](config.md) | The file is invalid (error printed to stderr). |
| [`aasm audit verify-chain`](audit.md) | The audit hash chain failed verification. |

## Command groups

| Command | Talks to | Purpose |
|---|---|---|
| [`aasm status`](status.md) | Gateway HTTP | Fleet health, agents, approvals, budget at a glance. |
| [`aasm agent`](agent.md) | Gateway HTTP | List, inspect, suspend, resume, kill registered agents. |
| [`aasm policy`](policy.md) | Gateway HTTP + local | Apply, version, diff, simulate, validate, show policies. |
| [`aasm topology`](topology.md) | Gateway HTTP | Visualize agent trees, teams, lineage, stats. |
| [`aasm alerts`](alerts.md) | Gateway HTTP | List, inspect, resolve governance alerts. |
| [`aasm approvals`](approvals.md) | Gateway HTTP + WS | Human-in-the-loop approval queue. |
| [`aasm audit`](audit.md) | Gateway HTTP + local | Query, export, verify, and compliance-export audit data. |
| [`aasm logs`](logs.md) | Gateway HTTP + WS | Query and stream audit-log events. |
| [`aasm trace`](trace.md) | Gateway HTTP | Visualize a single session trace. |
| [`aasm cost`](cost.md) | Gateway HTTP | Cost summary and monthly forecast. |
| [`aasm dashboard`](dashboard.md) | Gateway HTTP/WS + local | TUI dashboard and embedded SPA server. |
| [`aasm gateway`](gateway.md) | Local process | Manage the `aa-gateway` daemon. |
| [`aasm proxy`](proxy.md) | Local process | Manage the `aa-proxy` sidecar and its CA. |
| [`aasm start`](start-stop.md) / [`aasm stop`](start-stop.md) | Local process | Start/stop the locally-managed gateway. |
| [`aasm sandbox`](sandbox.md) | Local | Run a WASM tool under the sandbox. |
| [`aasm config`](config.md) | Local | Validate / boot an `agent-assembly.toml`. |
| [`aasm context`](context.md) | Local | Manage `~/.aa/config.yaml` contexts. |
| [`aasm admin`](admin.md) | Gateway HTTP | Administrative operations (retention). |
| [`aasm uninstall`](uninstall.md) | Local | Remove Agent Assembly tools installed via the curl installer (`--purge` also removes local data; Homebrew installs are redirected to `brew uninstall`). |
| [`aasm version`](version.md) | Gateway HTTP | CLI + gateway/api versions. |
| [`aasm completion`](completion.md) | Local | Generate shell completion scripts. |

> **Developer-only commands.** The source tree also defines `aasm run`
> (launch a governed AI dev tool) and `aasm tools` (discover installed AI dev
> tools). Both are gated behind the `devtool` region in
> `aa-cli/src/commands/mod.rs` and `aa-cli/Cargo.toml` and are **stripped from
> the published crate** by `.ci/strip-for-publish.sh` before release. They are
> intentionally **not documented** here because they are not part of the
> published `aasm` surface.
