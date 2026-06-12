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
NAME         API URL                       DEFAULT
production   https://api.example.com       *
staging      https://staging.example.com
```

---

## aasm context set

Create or update a named context.

| Name | Type | Default | Description |
|---|---|---|---|
| `<NAME>` | string (arg) | — | Name of the context to create or update. |
| `--api-url <API_URL>` | string | _required_ | API URL for this context. |
| `--api-key <API_KEY>` | string | — | API key for this context (optional). |

```bash
aasm context set staging --api-url https://staging.example.com
```

```text
Saved context 'staging'.
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
Default context set to 'production'.
```
