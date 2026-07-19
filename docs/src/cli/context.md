# aasm context

Manage named API contexts (connection profiles) stored in
`~/.aa/config.yaml`. A context bundles an API URL and optional API key under a
name so you can switch between gateways with `--context <name>`.

> See [Config and context resolution](overview.md#config-and-context-resolution)
> for how the active context is resolved.

## Synopsis

```text
aasm context <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`list`](#aasm-context-list) | List all configured contexts. |
| [`set`](#aasm-context-set) | Create or update a named context. |
| [`use`](#aasm-context-use) | Switch the default context. |

---

## aasm context list

List all configured contexts with their API URLs. Takes no arguments.

```bash
aasm context list
```

```text
production *  https://api.example.com (key set)
staging  https://staging.example.com
```

One line per context — no header row. A ` *` marker follows the default
context's name, and ` (key set)` follows the URL when an API key is stored for
that context. When no contexts are configured, `aasm context list` prints
`No contexts configured. Use \`aasm context set\` to add one.` instead.

---

## aasm context set

Create or update a named context.

| Name | Type | Default | Description |
|---|---|---|---|
| `<NAME>` | string (arg) | — | Name of the context to create or update. |
| `--api-url <API_URL>` | string | _required_ | API URL for this context. |
| `--api-key <API_KEY>` | string | — | API key for this context (optional). Prefer the `AASM_API_KEY` environment variable — see the note below. |

> **`AASM_API_KEY` env var.** When `--api-key` is omitted, `aasm context set`
> reads the key from the `AASM_API_KEY` environment variable (an empty value is
> treated as unset). Passing `--api-key` on the command line prints a warning
> and is discouraged, because argv is world-readable via `ps`,
> `/proc/<pid>/cmdline`, and shell history, which leaks the operator bearer
> token. The global [`--api-key`](overview.md#global-options) flag honors the
> same `AASM_API_KEY` env var.

```bash
AASM_API_KEY=staging-key aasm context set staging --api-url https://staging.example.com
```

```text
Context 'staging' saved.
```

---

## aasm context use

Switch the default context (the one used when `--context` is not passed).

| Argument | Type | Description |
|---|---|---|
| `<NAME>` | string | Name of the context to set as default. |

```bash
aasm context use production
```

```text
Switched to context 'production'.
```
