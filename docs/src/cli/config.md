# aasm config

Validate and boot an `agent-assembly.toml` runtime configuration file. These
operate on the **runtime** TOML (storage drivers, etc.) — distinct from the
CLI's own `~/.aa/config.yaml` connection profiles (see
[`aasm context`](context.md)).

## Synopsis

```text
aasm config <SUBCOMMAND>
```

| Subcommand | Purpose |
|---|---|
| [`validate`](#aasm-config-validate) | Validate an `agent-assembly.toml` (currently the `[storage]` section). |
| [`boot`](#aasm-config-boot) | Build the `[storage]` backends and run a sample policy lookup. |

---

## aasm config validate

Parse the TOML file and resolve every `[storage]` driver name against the
built-in driver registry. Exits `0` when valid; `1` with the error on stderr
otherwise. Unknown sections are ignored.

| Argument | Type | Description |
|---|---|---|
| `<FILE>` | path | Path to the `agent-assembly.toml` file to validate. |

```bash
aasm config validate ./agent-assembly.toml
```

```text
✓ agent-assembly.toml valid — storage driver: memory
```

---

## aasm config boot

Resolve every `[storage]` driver through the registry, build each backend, and
perform a sample policy lookup to confirm the configuration actually boots.
Exits `0` on success; `1` with the error on stderr.

| Argument | Type | Description |
|---|---|---|
| `<FILE>` | path | Path to the `agent-assembly.toml` file to boot from. |

```bash
aasm config boot ./agent-assembly.toml
```

```text
✓ booted storage backends; sample policy lookup OK
```
