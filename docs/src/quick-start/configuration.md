# Configuration

The `aasm` CLI works with **zero configuration** — if you never create a config
file, it talks to a gateway API at `http://localhost:8080`. This page covers the
config file format, named contexts (connection profiles), the environment
variables the CLI reads, and the separate `agent-assembly.toml` runtime config
the gateway consumes.

## Where the CLI connects, and how it decides

Every CLI command that talks to the control plane resolves three things — the
API URL, an optional API key, and an output format — from the following sources,
**highest priority first**:

1. Explicit flags: `--api-url`, `--api-key`.
2. A named context selected with `--context <name>`, or the `default_context`
   from the config file.
3. The built-in default API URL: `http://localhost:8080`.

So `aasm status` with no flags and no config file connects to
`http://localhost:8080`. A `--api-url` flag always wins over any context.

## The CLI config file: `~/.aa/config.yaml`

CLI configuration lives at `~/.aa/config.yaml`. The file is optional; if it is
absent the CLI uses defaults. Its schema:

```yaml
# Name of the context used when --context is not given (optional).
default_context: local

# Named connection profiles. Each has an api_url and an optional api_key.
contexts:
  local:
    api_url: http://localhost:8080
  production:
    api_url: https://api.example.com
    api_key: secret123        # optional; omit for unauthenticated endpoints

# Settings for `aasm dashboard start` (optional; shown with defaults).
dashboard:
  port: 3000
  auto_open: false
```

| Key | Type | Default | Purpose |
|---|---|---|---|
| `default_context` | string | _(none)_ | Context used when `--context` is not passed |
| `contexts.<name>.api_url` | string | — | Base URL of the gateway API for this context |
| `contexts.<name>.api_key` | string | _(none)_ | Bearer token sent with requests for this context |
| `dashboard.port` | integer | `3000` | Port the embedded dashboard SPA server listens on |
| `dashboard.auto_open` | bool | `false` | Open the browser automatically after the dashboard is ready |

## Named contexts (connection profiles)

A **context** is a named API URL + key, so you can switch between, say, a local
gateway and a hosted one without retyping flags. Manage contexts with
`aasm context`; the commands read and write `~/.aa/config.yaml` for you.

Create or update contexts:

```console
$ aasm context set local --api-url http://localhost:8080
Context 'local' saved.

$ aasm context set production --api-url https://api.example.com --api-key secret123
Context 'production' saved.
```

Choose the default context:

```console
$ aasm context use local
Switched to context 'local'.
```

List them (the `*` marks the default; keys are never printed, only flagged as set):

```console
$ aasm context list
local *  http://localhost:8080
production  https://api.example.com (key set)
```

Once a default is set, every command uses it. Override per-invocation with
`--context`:

```sh
aasm status                       # uses default context (local)
aasm status --context production  # one-off against production
aasm status --api-url http://localhost:9090   # ad-hoc URL, ignores contexts
```

## Environment variables

The CLI reads these environment variables. Where one overlaps a flag or config
value, the precedence is noted.

| Variable | Used by | Precedence |
|---|---|---|
| `AASM_API_KEY` | every `aasm` command (global `--api-key`) | The flag wins when both are set — but **prefer the env var**. See the warning below |
| `AASM_DASHBOARD_PORT` | `aasm dashboard` | Highest — beats `--port` and `dashboard.port` in config |
| `AASM_VERSION` / `AASM_INSTALL_DIR` | the [install script](installation.md) | Installer only |
| `AA_POLICY` | `aasm gateway start` | Default policy path; overridden by `--policy` |
| `AA_DATA_DIR` | gateway / proxy / dashboard | Directory for PID files and managed-process state |
| `AA_PROXY_ADDR` | `aasm proxy start` | Proxy listen address (default `127.0.0.1:8899`) |
| `AA_PROXY_GATEWAY_ENDPOINT` | `aasm proxy start` | Upstream gateway endpoint the proxy reports to (e.g. `http://127.0.0.1:50051`) |
| `AA_CA_DIR` | `aasm proxy` | Per-host CA material directory |
| `AASM_STATE_DIR` | `aasm uninstall`, `aa-proxy`, the integration receipt store | Root of Agent Assembly's local state (default `~/.aasm`). See below |
| `AA_DEVINT_ENABLED` | `aa-runtime` | Turns the Developer Integration API on. **Off by default**; nothing binds the socket unless this is set |
| `AA_DEVINT_SOCKET` | `aa-runtime` + DI-API clients | Overrides the DI-API socket path (default `~/.aa/run/devint.sock`) |
| `AA_DEVINT_TOKEN_FILE` | `aa-runtime` + DI-API clients | Overrides the DI-API capability-token (enrolment) file path (default: beside the socket) |

> **Pass the API key through the environment, not the command line.** `--api-key`
> puts the operator bearer token into `argv`, where it is readable by any local
> user via `ps` and `/proc/<pid>/cmdline`, and where your shell will persist it
> to history. `AASM_API_KEY` avoids all three. The flag still takes precedence
> when both are set, so existing scripts keep working — but a script that sets
> the variable is the one to write.

> The prefixes are a **rough** guide, not a rule: **`AASM_*`** is mostly the CLI
> surface and **`AA_*`** mostly the daemons the CLI launches. `AASM_STATE_DIR`
> is the clear exception — it names one state root shared by the CLI, the proxy
> and the dev-tool integration receipt store, so treat the prefix as a hint and
> the "Used by" column as the answer.

### `AASM_STATE_DIR` and the integration receipt store

`AASM_STATE_DIR` (default `~/.aasm`) is where Agent Assembly keeps local state
that is not configuration: the managed-gateway PID file, the installer's
self-copy that [`aasm uninstall`](../cli/uninstall.md) forwards to, the proxy's
per-integration MitM host lists, and the **Developer Integration receipts** under
`${AASM_STATE_DIR:-~/.aasm}/integrations/`.

A receipt names every file Agent Assembly governs on this host, which mechanism
it relies on, and where the trust material sits — a useful map for anyone
planning to defeat the integration. So the directory is held to **`0700`** and
each file to **`0600`**, and — as with the proxy's CA loader — the mode is
**re-asserted on every load**, not only at creation. A receipt restored from a
backup or copied in with loose permissions is tightened rather than silently
trusted across a restart.

The receipts deliberately do **not** live inside the tool's own configuration
tree: a record whose job is to say what `~/.claude/` should contain cannot itself
be one of the files being described, and removal has to be able to empty that
directory without deleting its own evidence.

> **Not a tamper control.** Each receipt carries a hash over its canonical form.
> That catches truncated writes, partial syncs and hand-edits — a corrupt receipt
> is *reported* rather than silently misread — but it is not a MAC. Anyone with
> the developer's UID can recompute it, and host-level tamper prevention is an
> explicit non-goal.

### The Developer Integration API variables

`AA_DEVINT_ENABLED`, `AA_DEVINT_SOCKET` and `AA_DEVINT_TOKEN_FILE` configure the
[Developer Integration API](../devtools/developer-integration-api.md) — the
separate Unix socket that [`aasm integrations`](../cli/integrations.md) and other
local clients use to install and inspect dev-tool integrations. It carries **no**
policy decisions and no agent-action traffic, and it is **off by default**:
`AA_DEVINT_ENABLED` is read at runtime startup and nothing binds the socket
without it.

If you relocate the socket with `AA_DEVINT_SOCKET`, you must preserve its
permissions — a `0700` directory and a `0600` socket. They are load-bearing: with
them gone the OS layer of the two-layer authentication is gone and only the
capability token remains. The token file (`AA_DEVINT_TOKEN_FILE`) is likewise
`0600`, and a token in a file readable by more than its owner is **refused rather
than used**, so a filesystem mistake cannot become a silent authentication
downgrade.

`AASM_CLAUDE_MANAGED_ROOT` is read by shipped code but is **not** a
configuration knob: it redirects where the Claude Code adapter *addresses* the
administrator-managed settings file, for tests. It cannot be used to escalate —
the macOS authority refuses to elevate for any target that is not the canonical
managed-settings path, so a redirected root makes the write ordinary and
unprivileged rather than pointing an authorized write somewhere else, and a plan
that sees a non-canonical root says so in a warning.

> Three similarly-named gateway-endpoint variables are **distinct** and not
> interchangeable: `AA_PROXY_GATEWAY_ENDPOINT` (the proxy's upstream gateway,
> above), `AA_GATEWAY_ENDPOINT` (used by the runtime / SDK client), and
> `AA_GATEWAY_URL` (used by the Windsurf devtool). Only
> `AA_PROXY_GATEWAY_ENDPOINT` affects `aasm proxy start`.

## Output format

Most list/get commands accept `--output table|json|yaml` (default `table`). Use
`json` or `yaml` for scripting:

```console
$ aasm version --output json
[
  {
    "component": "cli",
    "version": "0.0.1-beta.4",
    "status": "-"
  },
  ...
]
```

## Gateway runtime config: `agent-assembly.toml`

The CLI config above is about *how the CLI connects*. The **gateway** itself
reads a separate runtime config — `agent-assembly.toml` — that selects its
persistence backends. A starter file ships at the repo root as
[`agent-assembly.toml.example`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/agent-assembly.toml.example):

```toml
# agent-assembly.toml — example runtime configuration
[storage]
policy_store       = "redis"
audit_sink         = "postgres"
session_store      = "redis"
credential_store   = "postgres"
rate_limit_counter = "redis"
lifecycle_store    = "postgres"

# Per-driver connection settings live under [storage.<driver-name>].
[storage.redis]
url = "redis://localhost:6379"

[storage.postgres]
url = "postgresql://localhost:5432/assembly"
```

Each storage kind names a driver (`memory`, `redis`, or `postgres`); the runtime
resolves the name to a registered backend at boot, so you can switch backends
without recompiling.

### Validate it before you boot

Use `aasm config validate` to check an `agent-assembly.toml` (currently the
`[storage]` section) before starting the gateway:

```console
$ aasm config validate agent-assembly.toml.example
Config is valid: agent-assembly.toml.example
```

A valid file exits `0`; an invalid one reports the problem and exits non-zero.

## Next

You are configured. Walk through starting a gateway and observing an agent in
[First run](first-run.md).