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

### `aa-api` server environment variables

The REST API server (`aa-api`) — the process the dashboard reads through — reads
its own set of `AA_*` variables at boot. These configure the server itself, not
the CLI.

| Variable | Default | Purpose |
|---|---|---|
| `AA_POLICY` | _(unset)_ | Policy source for the API's dashboard projections. See [Policy source](#policy-source-for-aa-api) below. |
| `AA_AUTH_OPEN_REGISTRATION` | `false` | Opt into open self-registration for [native accounts](../usage-guide/authentication.md#opening-self-registration-optional). Only `1` / `true` / `yes` (case-insensitive) enable it; the default is closed (first-user-then-invite). |
| `AA_SMTP_HOST` | _(unset)_ | SMTP relay host. Its presence switches on real password-reset email delivery; when unset, `aa-api` falls back to a logging mailer that sends nothing. See [Password-reset email](../usage-guide/authentication.md#password-reset-email-smtp). |
| `AA_SMTP_PORT` | `587` | SMTP port (submission with STARTTLS). |
| `AA_SMTP_USER` | _(unset)_ | Username for authenticated SMTP submission. Optional. |
| `AA_SMTP_PASS` | _(unset)_ | Password for authenticated SMTP submission. Optional. |
| `AA_SMTP_FROM` | `no-reply@localhost` | The `From:` address stamped on outbound mail. |

> Native email/password accounts also require a **Postgres-backed** deployment.
> The `AA_SMTP_*` and `AA_AUTH_OPEN_REGISTRATION` variables only take effect once
> native accounts are available. See [Authentication](../usage-guide/authentication.md).

#### Policy source for `aa-api`

`aa-api` reads `AA_POLICY` the same way `aa-gateway` does — routing on the
**shape** of the path it points at — to decide what the dashboard's
capability-matrix, topology-chain, and team-policy projections display:

| `AA_POLICY` | What `aa-api` loads | What the projections show |
|---|---|---|
| **A directory** | The multi-document [policy cascade](../operations/policy-cascade-loader.md) (Global / Org / Team / Agent scopes) | Real cascade data — the enforced org/team/agent rules |
| **A single file** | That one policy document | The single policy's rules only (no cascade) |
| _(unset / empty / non-existent path)_ | A generated budget-only bootstrap policy | `Unknown` / `Unconfigured` — never a fabricated allow |

When `AA_POLICY` is unset, the projections render an honest "Unconfigured"
signal rather than presenting the generated bootstrap as though it were an
operator-authored policy. Point `AA_POLICY` at a directory to see the full
cascade in the dashboard.

#### Trust score tuning

The dashboard's per-agent **trust score** (a policy-friction score served at
`GET /api/v1/analytics/trust`) needs no configuration to work — every tenant
starts on sensible defaults. Its penalty-signal weights are optionally tunable
per tenant at runtime via `GET` / `PUT /api/v1/analytics/trust/config`; there is
no environment variable for it. An agent with fewer than the minimum number of
governed actions shows `—` (not enough data) rather than a misleading number.

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