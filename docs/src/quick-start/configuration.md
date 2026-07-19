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
| `AASM_DASHBOARD_PORT` | `aasm dashboard` | Highest — beats `--port` and `dashboard.port` in config |
| `AASM_VERSION` / `AASM_INSTALL_DIR` | the [install script](installation.md) | Installer only |
| `AA_POLICY` | `aasm gateway start` | Default policy path; overridden by `--policy` |
| `AA_DATA_DIR` | gateway / proxy / dashboard | Directory for PID files and managed-process state |
| `AA_PROXY_ADDR` | `aasm proxy start` | Proxy listen address (default `127.0.0.1:8899`) |
| `AA_PROXY_GATEWAY_ENDPOINT` | `aasm proxy start` | Upstream gateway endpoint the proxy reports to (e.g. `http://127.0.0.1:50051`) |
| `AA_CA_DIR` | `aasm proxy` | Per-host CA material directory |

> Note the two prefixes: **`AASM_*`** variables configure the CLI surface, while
> **`AA_*`** variables configure the underlying daemons the CLI launches
> (gateway, proxy). They are not interchangeable.

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
[`agent-assembly.toml.example`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/agent-assembly.toml.example):

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