# aasm policy

Manage governance policies — apply new versions, inspect history, roll back,
diff, simulate, validate locally, and view effective policy.

## Synopsis

```text
aasm policy <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`apply`](#aasm-policy-apply) | Apply a policy YAML file and save it to version history. |
| [`history`](#aasm-policy-history) | List recent policy versions. |
| [`rollback`](#aasm-policy-rollback) | Roll back to a previous version. |
| [`diff`](#aasm-policy-diff) | Show the diff between two versions. |
| [`simulate`](#aasm-policy-simulate) | Dry-run a policy against historical events or live traffic. |
| [`validate`](#aasm-policy-validate) | Validate a policy YAML file locally (no apply). |
| [`get`](#aasm-policy-get) | Show the active policy YAML (or a specific version). |
| [`list`](#aasm-policy-list) | List all deployed policies. |
| [`show`](#aasm-policy-show) | Show an agent's effective policy view. |

All subcommands accept the [global options](overview.md#global-options).

---

## aasm policy apply

Apply a policy YAML file and save it to version history.

| Name | Type | Default | Description |
|---|---|---|---|
| `<FILE>` | path (arg) | — | Path to the policy YAML file. |
| `--applied-by <APPLIED_BY>` | string | — | Identity of the person or system applying the policy. |

```bash
aasm policy apply ./policies/prod.yaml --applied-by alice@example.com
```

```text
Applied policy 9f2c1a (version 2026-06-09T14:00:00Z) — active, 12 rules
```

---

## aasm policy history

List recent policy versions.

| Name | Type | Default | Description |
|---|---|---|---|
| `-n, --limit <LIMIT>` | integer | `10` | Maximum number of versions to show. |

```bash
aasm policy history -n 5
```

---

## aasm policy rollback

Roll back to a previous policy version, making it active again.

| Name | Type | Description |
|---|---|---|
| `<VERSION>` | string (arg) | Version identifier (SHA-256 prefix) to roll back to. |

```bash
aasm policy rollback 9f2c1a
```

---

## aasm policy diff

Show a colorized unified diff between two policy versions. Colors are
suppressed when stdout is not a TTY.

| Name | Type | Description |
|---|---|---|
| `<VERSION_A>` | string (arg) | First version identifier (SHA-256 prefix). |
| `<VERSION_B>` | string (arg) | Second version identifier (SHA-256 prefix). |

```bash
aasm policy diff 9f2c1a 7ab310
```

---

## aasm policy simulate

Simulate a policy against historical audit events or live traffic without
enforcing it. **Exits non-zero if the simulation detects any violation**, so
it can gate a CI pipeline.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--policy <POLICY>` | path | _required_ | Path to the policy YAML file to simulate. |
| `--against <AGAINST>` | path | — | Audit-log JSONL file to replay against the policy. |
| `--live` | flag | `false` | Observe live agent traffic instead of replaying a file. |
| `--duration <DURATION>` | string | — | Duration for live simulation (e.g. `60s`, `5m`). |
| `--output-file <OUTPUT_FILE>` | path | — | Write the simulation report JSON here. (Named `--output-file` to avoid colliding with the global `--output`.) |

```bash
aasm policy simulate --policy ./candidate.yaml --against ./audit/session.jsonl
```

```text
Simulation: 412 events, 3 would-be violations
  deny  file_write  /etc/passwd   (rule: block-system-paths)
exit status: 1
```

---

## aasm policy validate

Validate a policy YAML file locally (no apply, no gateway contact). Exits `0`
when valid, `1` with error details on stderr otherwise.

| Name | Type | Description |
|---|---|---|
| `<FILE>` | path (arg) | Path to the policy YAML file to validate. |

```bash
aasm policy validate ./policies/prod.yaml
```

```text
✓ policy valid — 12 rules
```

---

## aasm policy get

Show the currently active policy YAML, or a specific version.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--version <VERSION>` | string | _(latest active)_ | Version identifier (SHA-256 prefix) to retrieve. Omit for the active policy. |

```bash
aasm policy get --version 9f2c1a
```

---

## aasm policy list

List all policies deployed to the governance runtime. Takes no flags of its
own (uses the global `--output`).

```bash
aasm policy list --output json
```

```text
NAME      VERSION                  ACTIVE   RULES
9f2c1a    2026-06-09T14:00:00Z     yes      12
7ab310    2026-06-01T09:30:00Z     no       11
```

---

## aasm policy show

Show an agent's effective policy view. By default prints the agent identity;
add a flag to expand into the capability cascade or budget rollup.

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Hex-encoded agent UUID (32 hex characters). |
| `--show-permissions` | flag | off | Print the effective capability set with cascade provenance (granted-by / denied-by scope). |
| `--show-budget` | flag | off | Print the budget rollup across agent / team / org / subtree. |

```bash
aasm policy show a1b2c3… --show-permissions
```

```text
Capability        Effective   Granted by      Denied by
search            Allow       team:research   —
file_write        Deny        —               org
```
