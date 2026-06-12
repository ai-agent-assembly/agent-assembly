# aasm approvals

Manage human-in-the-loop approval requests — list pending actions, approve or
reject them, and watch for new requests in real time.

## Synopsis

```text
aasm approvals <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`list`](#aasm-approvals-list) | List pending (or resolved) approval requests. |
| [`get`](#aasm-approvals-get) | Show details of one request. |
| [`approve`](#aasm-approvals-approve) | Approve a pending action. |
| [`reject`](#aasm-approvals-reject) | Reject a pending action. |
| [`watch`](#aasm-approvals-watch) | Watch for new approval requests over WebSocket. |

All subcommands accept the [global options](overview.md#global-options).

---

## aasm approvals list

List approval requests as a colored table. The `TIMEOUT_IN` column is
color-coded (red < 60s, yellow 60–180s, green > 180s).

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output <FORMAT>` | `table` \| `json` \| `yaml` | global default | Per-command output override. |
| `--status <STATUS>` | `pending` \| `approved` \| `rejected` | `pending` | Filter by lifecycle status. Resolved history is bounded (default cap 1000). |
| `--agent <AGENT>` | string | — | Filter to approvals submitted by this agent ID (exact match). |

```bash
aasm approvals list --status pending
```

```text
ID        AGENT      ACTION        CONDITION       SUBMITTED_AT          TIMEOUT_IN
ap-77     a1b2c3…    file_write    /etc/hosts      2026-06-09T14:01:00Z  2m 30s
```

---

## aasm approvals get

Show details of a single pending approval request.

| Name | Type | Default | Description |
|---|---|---|---|
| `<ID>` | string (arg) | — | Approval request ID to look up. |
| `--output <FORMAT>` | `table` \| `json` \| `yaml` | global default | Per-command output override. |

```bash
aasm approvals get ap-77
```

---

## aasm approvals approve

Approve a pending action.

| Name | Type | Default | Description |
|---|---|---|---|
| `<ID>` | string (arg) | — | Approval request ID to approve. |
| `--reason <REASON>` | string | — | Optional reason. May also be supplied on piped stdin. |

```bash
aasm approvals approve ap-77 --reason "verified safe"
```

```text
Approved ap-77.
```

---

## aasm approvals reject

Reject a pending action. A reason is **required** in non-interactive mode
(supply `--reason` or pipe it on stdin).

| Name | Type | Default | Description |
|---|---|---|---|
| `<ID>` | string (arg) | — | Approval request ID to reject. |
| `--reason <REASON>` | string | _required (non-interactive)_ | Reason for rejection. May also be piped on stdin. |

```bash
aasm approvals reject ap-77 --reason "writes outside allowed path"
```

```text
Rejected ap-77.
```

---

## aasm approvals watch

Watch for new approval requests in real time over the gateway WebSocket
events endpoint (filtered to `approval` events).

| Flag | Type | Default | Description |
|---|---|---|---|
| `-i, --interactive` | flag | off | Enable interactive mode with keyboard shortcuts (`a`=approve, `r`=reject, `q`=quit; arrow keys navigate). |

```bash
aasm approvals watch --interactive
```

```text
▶ ap-78  a1b2c3…  network_egress  api.openai.com   3m 00s
  a approve   r reject   ↑/↓ select   q quit
```
