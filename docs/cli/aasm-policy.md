# `aasm policy`

<a id="cmd-aasm-policy"></a>

Manage governance policies

## Synopsis

```text
Usage: aasm policy <COMMAND>
```

## Subcommands

| Command | Description |
|---------|-------------|
| [`aasm policy apply`](aasm-policy-apply.md#cmd-aasm-policy-apply) | Apply a policy YAML file and save it to version history |
| [`aasm policy history`](aasm-policy-history.md#cmd-aasm-policy-history) | List recent policy versions |
| [`aasm policy rollback`](aasm-policy-rollback.md#cmd-aasm-policy-rollback) | Roll back to a previous policy version |
| [`aasm policy diff`](aasm-policy-diff.md#cmd-aasm-policy-diff) | Show the diff between two policy versions |
| [`aasm policy simulate`](aasm-policy-simulate.md#cmd-aasm-policy-simulate) | Simulate a policy against historical events or live traffic (dry-run) |
| [`aasm policy validate`](aasm-policy-validate.md#cmd-aasm-policy-validate) | Validate a policy YAML file locally (no apply) |
| [`aasm policy get`](aasm-policy-get.md#cmd-aasm-policy-get) | Show the currently active policy YAML (or a specific version) |
| [`aasm policy list`](aasm-policy-list.md#cmd-aasm-policy-list) | List all policies deployed to the governance runtime |
| [`aasm policy show`](aasm-policy-show.md#cmd-aasm-policy-show) | Show an agent's effective policy view (use `--show-permissions`) |

