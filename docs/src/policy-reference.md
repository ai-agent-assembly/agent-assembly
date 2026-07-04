# Policy YAML Reference

A complete reference for the governance policy document the gateway loads,
validates, and enforces. Every field below is grounded in the policy engine's
own types (`aa-gateway/src/policy/`) and the shared core
(`aa-core`). Validate any file locally before applying it:

```bash
aasm policy validate path/to/policy.yaml
```

Validation prints `Policy is valid: <path>` and exits `0` on success. Hard
constraint violations print `error: <field>: <message>` and exit `1`.
Unrecognised keys are **warnings**, not errors — the file still validates, but
the unknown key is ignored at runtime, so a typo'd field silently does nothing.
Treat warnings as bugs.

## Document formats

A policy may be written in either of two equivalent shapes.

### Envelope format (recommended)

A Kubernetes-style wrapper. `metadata.name` and `metadata.version` are surfaced
in tooling; the actual policy lives under `spec:`.

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: my-policy
  version: "1.0.0"
  description: Optional free text.
spec:
  budget:
    daily_limit_usd: 20.0
```

### Flat format

The same content with no wrapper — every section sits at the top level. There
is no `metadata`, so `name` and `version` are absent.

```yaml
version: "1.0"
budget:
  daily_limit_usd: 20.0
```

The validator auto-detects the format: if a top-level `spec:` key is present it
parses the envelope, otherwise it parses the flat form. The field tables below
describe the policy body (the content of `spec:`, or the whole document in flat
form).

## Top-level fields

| Field | Type | Default | Example |
|---|---|---|---|
| `version` | string | _(none)_ | `version: "1.0"` |
| `scope` | string | `global` | `scope: team:platform` |
| `approval_timeout_secs` | integer > 0 | `300` | `approval_timeout_secs: 600` |
| `network` | section | _(omitted → unrestricted)_ | see [network](#network) |
| `schedule` | section | _(omitted → always active)_ | see [schedule](#schedule) |
| `budget` | section | _(omitted → no cap)_ | see [budget](#budget) |
| `data` | section | _(omitted → no scan rules)_ | see [data](#data) |
| `tools` | map | _(empty)_ | see [tools](#tools) |
| `capabilities` | section | _(omitted)_ | see [capabilities](#capabilities) |
| `approval` | section | _(omitted)_ | see [approval](#approval) |

`scope` accepts one of: `global`, `org:<id>`, `team:<id>`, `agent:<uuid>`, or
`tool:<name>`. The cascade evaluates policies in
`Global → Org → Team → Agent → Tool` order, most-restrictive-wins. An `agent:`
scope requires a valid hyphenated UUID; a `team:`/`org:`/`tool:` identifier must
not be empty. Any other shape is a validation error.

## Complete example policy

A single policy exercising every section. This validates cleanly.

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: complete-example
  version: "1.0.0"
  description: Demonstrates every policy section.
spec:
  scope: team:platform
  approval_timeout_secs: 300

  network:
    allowlist:
      - api.openai.com
      - "*.anthropic.com"

  schedule:
    active_hours:
      start: "09:00"
      end: "18:00"
      timezone: "Asia/Taipei"

  budget:
    daily_limit_usd: 25.0
    monthly_limit_usd: 500.0
    timezone: "Asia/Taipei"
    action_on_exceed: deny

  data:
    credential_action: redact_only
    sensitive_patterns:
      - "sk-[A-Za-z0-9]{20,}"

  capabilities:
    allow:
      - file_read
      - network_outbound
      - mcp_tool:git
    deny:
      - terminal_exec

  approval:
    timeout_seconds: 600
    escalation_role: org-admin

  tools:
    read_file:
      allow: true
      limit_per_hour: 120
    write_file:
      allow: true
      requires_approval_if: "path starts_with \"/etc\""
    shell:
      allow: false
```

## `network`

Controls outbound (egress) connections. Backed by `NetworkPolicy`.

| Field | Type | Default | Example |
|---|---|---|---|
| `allowlist` | list of glob strings | `[]` | `allowlist: ["api.openai.com"]` |

### Glob pattern semantics

The matcher (`aa_core::policy::is_host_allowed_by_egress_allowlist`) supports
exactly three pattern shapes:

| Pattern | Matches | Does **not** match |
|---|---|---|
| `api.openai.com` | exact host, case-insensitive | `chat.openai.com`, `openai.com` |
| `*.openai.com` | any sub-domain at any depth: `api.openai.com`, `a.b.openai.com` | the bare apex `openai.com`; attacker suffixes like `evilopenai.com` |
| `*` | every host (escape hatch) | — |

Matching is case-insensitive (DNS labels are case-insensitive per RFC 4343).
The leftmost-label wildcard `*.` requires at least one label before the suffix,
so `*.openai.com` deliberately excludes the bare `openai.com` — list both if you
need the apex too.

### Default behavior

- **No `network:` section** → egress is **unrestricted** (default-open). The
  caller's posture wins.
- **`network:` present but `allowlist` empty or omitted** → also unrestricted.
  An empty list means "no restriction", **not** "deny all". To deny by default,
  list only the hosts you trust — anything not matched is then denied.

An allowlist entry that is empty or whitespace-only is a validation error
(`network.allowlist[i]: allowlist entry must not be empty`).

## `tools`

Per-tool allow/deny, rate limiting, and approval gating. A map keyed by tool
name; each value is a `ToolPolicy`.

| Field | Type | Default | Example |
|---|---|---|---|
| `allow` | bool | `true` | `allow: false` |
| `limit_per_hour` | integer | _(unlimited)_ | `limit_per_hour: 10` |
| `requires_approval_if` | expression string | _(never)_ | `requires_approval_if: "path starts_with \"/etc\""` |

`allow` defaults to `true` when omitted, so a tool entry that only sets
`limit_per_hour` is still permitted.

### The `*` wildcard tool

A tool named `*` is the catch-all entry for any tool without its own named
rule. Pair `"*": { allow: false }` with explicit `allow: true` entries to get
deny-by-default behaviour (see the [Strict example](#strict)). Conversely
`"*": { allow: true }` is an explicit allow-everything default.

```yaml
tools:
  "*":
    allow: false      # deny every tool not named below
  read_file:
    allow: true       # ...except read_file
```

### `requires_approval_if` expression syntax

`requires_approval_if` holds a boolean expression evaluated against the
in-flight action. When it evaluates **true**, the action is routed to
human-in-the-loop approval instead of executing immediately. The expression is
parsed and **validated at load time** (`aa-gateway/src/policy/expr.rs`): an
empty expression, an unknown variable, or an unknown governance level (`L4`+) is
a hard validation error.

> **Fail-safe at runtime:** if the engine cannot evaluate an expression (parse
> error, malformed action), it returns **true** — approval required — never a
> silent allow.

#### Grammar

```text
expr       := clause (combinator clause)*
clause     := field op literal
combinator := AND | OR          # AND binds tighter than OR; no parentheses
```

`AND`/`OR` are uppercase. There are no parentheses in this version; an
expression is OR-groups of AND-connected clauses.

#### Operators

| Operator | Meaning | Operand types |
|---|---|---|
| `==` | equal | string, number, governance level, risk tier |
| `!=` | not equal | string, number, governance level, risk tier |
| `>` `>=` `<` `<=` | ordered comparison | number, governance level, risk tier, duration |
| `contains` | substring / membership | string |
| `starts_with` | prefix match | string |
| `in` | value in list | string against `["a", "b"]` |
| `not_in` | value not in list | string against `["a", "b"]` |

#### Literals

- **String**: double-quoted, e.g. `"/etc"`. Escapes: `\"` and `\\`.
- **Number**: integer or float, e.g. `10`, `1.5`.
- **List**: `["read", "write"]` — for `in` / `not_in`.
- **Governance level**: `L0`, `L1`, `L2`, `L3` (ordered). Any other `L<n>` is a
  validation error.
- **Risk tier**: `Low`, `Medium`, `High`, `Critical` (ordered).
- **Duration**: human-readable, digit-leading, e.g. `24h`, `30m`, `1h30m`
  (compared as seconds — `24h` == `86400`).

#### Operands (variables)

The variable on the left of each clause must be one of the names the evaluator
knows. Unknown names are rejected at load time (with a typo suggestion when
close). The recognised variables:

| Variable | Resolves against | Type |
|---|---|---|
| `tool` | the called tool's name | string |
| `path` | a file-access path | string |
| `url` | a network-request URL | string |
| `method` | a network-request HTTP method | string |
| `command` | a process-exec command line | string |
| `args.<key>[.<nested>]` | a JSON field inside a tool call's `args` body | string / number |
| `tool_result.<key>[.<nested>]` | a JSON field inside a tool result | string / number |
| `tool_result` | the entire serialised tool-result body | string (`contains`/`starts_with` only) |
| `governance_level` | the agent's governance level | level (`L0`–`L3`) |
| `agent.depth` | delegation depth | number |
| `agent.risk_tier` | the agent's risk tier | tier |
| `agent.age` | seconds since the agent registered | number / duration |
| `agent.parent_agent_id` | the agent's parent id | string |
| `agent.team_id` | the agent's team id | string |
| `agent.children_count` | number of direct children | number |
| `agent.is_root` | `1` when depth == 0, else `0` | number (`==`/`!=`) |
| `agent.is_leaf` | `1` when children_count == 0, else `0` | number (`==`/`!=`) |
| `team.active_agents` | running agents in the team | number |
| `team.parallel_agents` | alias of `team.active_agents` | number |
| `team.budget_remaining` | remaining monthly budget | number |
| `child.tool` | tool names across direct children | string |
| `child.risk_tier` | risk tier of a child being spawned | tier |
| `parent.risk_tier` | the parent agent's risk tier | tier |
| `source.team_id` | sending team of a message | string |
| `target.team_id` | recipient team of a message | string |
| `target.channel_id` | message channel id | string |

The `args.<key>` and `tool_result.<key>` forms walk a JSON pointer
(`args.path` → `/path`, `args.headers.authorization` →
`/headers/authorization`). They are **null-safe**: a non-matching action variant,
malformed JSON, or an unresolved pointer evaluates to **false** (no match), not
fail-safe-true.

#### Example expressions

Each of the following is a valid `requires_approval_if` value:

1. `"path starts_with \"/etc\""` — gate writes under `/etc`.
2. `"args.path contains \"/etc\""` — same idea, reading the path out of a tool
   call's JSON `args`.
3. `"command contains \"sudo\""` — gate any shell command invoking `sudo`.
4. `"url contains \"internal\""` — gate requests to internal hosts.
5. `"tool == \"delete_database\""` — gate one specific tool by name.
6. `"agent.depth > 1"` — gate actions from agents deeper than one delegation hop.
7. `"agent.children_count > 10"` — gate agents that have spawned many children.
8. `"governance_level >= L2"` — gate when the agent runs at L2 (Enforce) or above.
9. `"agent.risk_tier >= High"` — gate high- and critical-risk agents.
10. `"agent.age < 24h"` — gate brand-new agents (registered under a day ago).
11. `"method == \"DELETE\" OR method == \"PUT\""` — gate destructive HTTP verbs.
12. `"target.team_id in [\"finance\", \"security\"]"` — gate messages sent to
    sensitive teams.
13. `"tool_result contains \"sk-\""` — gate when the response body looks like it
    carries a secret.
14. `"command contains \"rm\" AND agent.is_root == 0"` — gate `rm` from non-root
    (delegated) agents only.

> **Divergence note.** Earlier drafts of this ticket used illustrative
> expressions such as `"call_count > 10"`. There is no `call_count` variable in
> the engine; per-tool rate limiting is expressed with the `limit_per_hour`
> field instead, and "how many children" is `agent.children_count`. Only the
> variables in the table above are accepted — anything else fails validation.

## `data`

Sensitive-data / credential handling. Backed by `DataPolicy`.

| Field | Type | Default | Example |
|---|---|---|---|
| `sensitive_patterns` | list of regex strings | `[]` | `sensitive_patterns: ["sk-[A-Za-z0-9]{20,}"]` |
| `credential_action` | enum | `redact_only` | `credential_action: block` |

### `credential_action` values

| Value | Behaviour |
|---|---|
| `block` | Refuse the action; the engine returns `Deny` (reason `credential detected`) and the payload never reaches upstream. |
| `redact_only` | **(default)** Forward a redacted form of the payload upstream. Preserves historical behaviour. |
| `alert_only` | Forward the unmodified payload and raise an alert. A deliberate downgrade for low-risk, audit-only modes. |

Any other value is a validation error.

### `sensitive_patterns` regex syntax

Each entry is a regular expression compiled by the Rust `regex` crate (RE2-style
— linear-time, no backtracking, no look-around or backreferences). An invalid
regex is a hard validation error
(`data.sensitive_patterns[i]: invalid regex: ...`). Backslashes must be escaped
for YAML, e.g. a US-SSN pattern is written `"\\b\\d{3}-\\d{2}-\\d{4}\\b"`.

### Built-in vs custom

The runtime ships a **built-in credential scanner** (`aa-security`) that always
runs, independent of `sensitive_patterns`. It is an Aho-Corasick literal matcher
covering common high-confidence secret prefixes, including:

- API keys: `sk-` (OpenAI), `sk-ant-` (Anthropic), `AKIA…` (AWS), GCP service
  accounts, Azure connection strings.
- Tokens: `ghp_` / `ghs_` (GitHub), `xoxb-` / `xoxp-` / `xoxa-` (Slack).
- Database URLs: `postgres://`, `mysql://`, `mongodb://`.
- Private keys: RSA, EC, OpenSSH, PKCS#8, PGP PEM blocks.

`sensitive_patterns` is the **custom** layer on top: your own regexes for
organisation-specific identifiers (employee IDs, internal hostnames, PII shapes
like SSNs or emails) that the built-in literal set does not cover.

### Performance notes

- The built-in scanner is **pre-compiled once** at construction; each scan pays
  **zero pattern-compilation cost** and runs in a single Aho-Corasick pass.
- Custom `sensitive_patterns` are compiled by the `regex` crate. Because that
  engine is backtracking-free, match time is **linear** in the input length —
  there is no catastrophic-backtracking risk. Still, keep the pattern list small
  and anchored where possible; each pattern is an independent scan over the
  payload.

## `budget`

Spend limits in **US dollars**. Backed by `BudgetPolicy`.

| Field | Type | Default | Example |
|---|---|---|---|
| `daily_limit_usd` | float > 0 | _(no cap)_ | `daily_limit_usd: 20.0` |
| `monthly_limit_usd` | float > 0, ≥ daily | _(no cap)_ | `monthly_limit_usd: 400.0` |
| `org_daily_limit_usd` | float > 0 | _(no cap)_ | `org_daily_limit_usd: 100.0` |
| `org_monthly_limit_usd` | float > 0, ≥ org daily | _(no cap)_ | `org_monthly_limit_usd: 2000.0` |
| `timezone` | IANA tz string | `UTC` | `timezone: "America/New_York"` |
| `action_on_exceed` | enum | `deny` | `action_on_exceed: suspend` |
| `window` | duration string | _(calendar day)_ | `window: "1h30m"` |

### Currency

All limits are USD. There is no currency selector — costs are computed from a
USD pricing table and compared against these USD caps.

### Per-agent vs global vs per-org

Spend is tracked per agent, and rolled up to team, org, and global totals.

- `daily_limit_usd` / `monthly_limit_usd` are the **global** caps (applied to
  the aggregate).
- `org_daily_limit_usd` / `org_monthly_limit_usd` add an **independent per-org**
  cap, enforced separately from the global cap. Either can trip first.

### Timezone & reset behaviour

`timezone` (an IANA name such as `Europe/London`) sets the boundary at which the
daily and monthly counters reset. It defaults to `UTC`. An unparseable name is a
validation error (`budget.timezone: '<x>' is not a valid IANA timezone name`).

- **Daily reset**: counters reset at local midnight in the configured timezone.
  Reset is **lazy** — it happens on the next spend event once the stored date is
  earlier than "today" in that timezone, so an idle agent's counter simply
  carries the old date until its next request.
- **Monthly reset**: triggers when the stored month differs from the current
  month in the configured timezone.
- **`window`** overrides the calendar-day rollover with a fixed rolling window
  (humantime duration, e.g. `5s`, `30m`, `1h`). Must be a positive duration.

### `action_on_exceed`

| Value | Behaviour |
|---|---|
| `deny` | **(default)** Deny individual over-budget requests but keep the agent active. |
| `suspend` | Suspend the agent entirely until the budget resets. |

Validation rules: every limit must be `> 0`; `monthly_limit_usd` must be
`≥ daily_limit_usd` (and the same for the org pair). Equal monthly/daily is
allowed; monthly without daily is allowed.

## `schedule`

Time-of-day gating. Backed by `SchedulePolicy` → `ActiveHours`.

| Field | Type | Default | Example |
|---|---|---|---|
| `active_hours.start` | `HH:MM` 24h | _(required if `active_hours` present)_ | `start: "09:00"` |
| `active_hours.end` | `HH:MM` 24h | _(required if `active_hours` present)_ | `end: "18:00"` |
| `active_hours.timezone` | IANA tz string | _(required if `active_hours` present)_ | `timezone: "Asia/Taipei"` |

When `active_hours` is set, the agent is permitted to run only inside the
`[start, end)` window in the given timezone. Omitting `schedule` entirely means
the agent is always active.

### Validation rules

- `start` and `end` must be **zero-padded** `HH:MM` (e.g. `09:00`, not `9:00`),
  hours `00–23`, minutes `00–59`.
- `start` must be **earlier than** `end` (string comparison on `HH:MM`). A
  window that wraps past midnight (e.g. `22:00`–`06:00`) is rejected — model
  overnight coverage as two policies or a single all-hours policy instead.
- All three fields are required once `active_hours` is present.

### IANA timezone strings

Use canonical IANA names: `UTC`, `America/New_York`, `Europe/London`,
`Asia/Taipei`, `Asia/Tokyo`, etc. Fixed offsets like `GMT+8` are **not** IANA
names and should be avoided.

### Multiple active windows

A single policy expresses **one** window. To grant several disjoint windows
(e.g. a morning and an afternoon block), apply multiple policies at different
scopes in the cascade, or widen to a single enclosing window.

### DST & timezone edge cases

Because the window is interpreted in a named IANA zone (not a fixed offset), it
follows daylight-saving transitions automatically — `09:00`–`18:00` stays
"9am to 6pm local" across the spring-forward and fall-back shifts. Two edge
cases are inherent to wall-clock time:

- **Spring forward** (clocks jump, e.g. `02:00`→`03:00`): a `start`/`end` that
  names the skipped hour refers to a wall-clock time that does not exist on that
  date. Prefer windows outside the local DST gap.
- **Fall back** (clocks repeat an hour): a time inside the repeated hour occurs
  twice. The window still opens and closes, but the repeated wall-clock hour is
  ambiguous. Avoid placing a boundary inside the local fall-back hour for
  predictable behaviour.

Keeping boundaries away from the very early-morning DST transition hours sidesteps
both cases.

## `capabilities`

Coarse-grained allow/deny of action categories. Backed by
`aa_core::CapabilitySet`. Merged across the scope cascade with
parent-deny-wins semantics.

| Field | Type | Default | Example |
|---|---|---|---|
| `allow` | list of capability strings | `[]` | `allow: ["file_read"]` |
| `deny` | list of capability strings | `[]` | `deny: ["terminal_exec"]` |

Recognised capability strings:

| String | Capability |
|---|---|
| `file_read` | read the filesystem |
| `file_write` | write (create / truncate / append) the filesystem |
| `file_delete` | delete / unlink files from the filesystem |
| `network_outbound` | outbound network |
| `network_inbound` | inbound network |
| `terminal_exec` | execute shell commands |
| `agent_spawn` | spawn child agents |
| `mcp_tool:<name>` | use a named MCP tool, e.g. `mcp_tool:git` |
| `model:<name>` | use a named model, e.g. `model:gpt-4o` |

An unknown capability string, or an `mcp_tool:` / `model:` with an empty name,
is a validation error.

`file_delete` is a distinct verb from `file_write`, so a policy can allow writes
while denying deletes (or the reverse). Two fail-closed rules apply:

- A `file_write` **allow** does **not** grant delete — a delete action is denied
  unless the policy explicitly allows `file_delete`.
- A `file_write` **deny** still blocks delete (defense in depth), so a policy
  that denies `file_write` to lock down all mutations keeps blocking deletes
  even if it never names `file_delete`.

To allow writes but forbid deletion:

```yaml
capabilities:
  allow:
    - file_read
    - file_write
  deny:
    - file_delete
```

## `approval`

Per-policy overrides for the approval-escalation routing. Backed by
`ApprovalPolicy`. When omitted, team routing defaults apply.

| Field | Type | Default | Example |
|---|---|---|---|
| `timeout_seconds` | integer | _(team default)_ | `timeout_seconds: 600` |
| `escalation_role` | string | _(team default)_ | `escalation_role: org-admin` |

Note the distinction between the top-level `approval_timeout_secs` (the global
approval timeout for the document, default `300`) and the `approval.timeout_seconds`
override inside this section.

## Three complete example policies

These ship under `policy-examples/` and all pass `aasm policy validate`.

### Strict

Deny all unknown tools, $5/day budget, block all sensitive data. See
[`policy-examples/strict.yaml`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/policy-examples/strict.yaml).

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: strict
  version: "1.0.0"
  description: >
    Lock everything down. Deny all unknown tools, cap spend at $5/day,
    and block any payload that trips the sensitive-data scanner. Use this
    as the baseline for high-risk or untrusted agents.
spec:
  scope: global

  network:
    # Empty-but-present allowlist still allows any host (an empty list means
    # "no restriction"). To actually restrict egress, list the exact hosts.
    allowlist:
      - api.openai.com
      - api.anthropic.com

  budget:
    daily_limit_usd: 5.0
    monthly_limit_usd: 100.0
    timezone: "UTC"
    action_on_exceed: suspend

  data:
    # Block the payload outright when the scanner finds a credential.
    credential_action: block
    sensitive_patterns:
      - "sk-[A-Za-z0-9]{20,}"
      - "AKIA[0-9A-Z]{16}"
      - "-----BEGIN [A-Z ]*PRIVATE KEY-----"

  # Capability floor: deny the dangerous categories regardless of per-tool rules.
  capabilities:
    deny:
      - terminal_exec
      - file_write
      - network_inbound

  # Deny every tool that is not explicitly allowed below.
  tools:
    "*":
      allow: false
    read_file:
      allow: true
      limit_per_hour: 60
    http_get:
      allow: true
      limit_per_hour: 30
      requires_approval_if: "url contains \"internal\""
```

### Balanced

Allowlist common tools, $20/day budget, PII detection on (redact). See
[`policy-examples/balanced.yaml`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/policy-examples/balanced.yaml).

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: balanced
  version: "1.0.0"
  description: >
    A pragmatic default for trusted internal agents. Allowlist the common
    tools, cap spend at $20/day, and detect PII / credentials by redacting
    rather than blocking so workflows keep running.
spec:
  scope: global

  network:
    allowlist:
      - api.openai.com
      - "*.anthropic.com"
      - "*.slack.com"
      - api.github.com

  schedule:
    active_hours:
      start: "08:00"
      end: "20:00"
      timezone: "America/New_York"

  budget:
    daily_limit_usd: 20.0
    monthly_limit_usd: 400.0
    timezone: "America/New_York"
    action_on_exceed: deny

  data:
    # Redact-only: forward a scrubbed payload upstream instead of refusing it.
    credential_action: redact_only
    sensitive_patterns:
      # PII detection: US SSN and a generic email address.
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"

  tools:
    read_file:
      allow: true
      limit_per_hour: 120
    http_get:
      allow: true
      limit_per_hour: 60
    web_search:
      allow: true
      limit_per_hour: 30
    write_file:
      allow: true
      requires_approval_if: "path starts_with \"/etc\" OR path contains \"..\""
    shell:
      allow: true
      limit_per_hour: 10
      requires_approval_if: "command contains \"rm\" OR command contains \"sudo\""
```

### Audit-only

Log everything, enforce nothing. See
[`policy-examples/audit-only.yaml`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/policy-examples/audit-only.yaml).

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: audit-only
  version: "1.0.0"
  description: >
    Observe everything, enforce nothing. Every tool is allowed and the
    sensitive-data scanner only raises an alert without modifying or blocking
    the payload. Use this to map an agent's behaviour before tightening rules.
spec:
  scope: global

  # No `network:` clause → egress is unrestricted (default-open).
  # No `budget:` clause → no spend cap is enforced.

  data:
    # alert_only: forward the unmodified payload and raise an alert side-effect.
    # Deliberate downgrade documented for low-risk, audit-only modes.
    credential_action: alert_only
    sensitive_patterns:
      - "sk-[A-Za-z0-9]{20,}"

  tools:
    # Wildcard allow: every tool is permitted; findings are logged, not enforced.
    "*":
      allow: true
```

## See also

- [L0–L3 Capability Matrix](governance/capability-matrix.md) — what each
  governance level can do.
- [Policy RBAC Role Matrix](policy-rbac.md) — who may mutate policy at each scope.
- [`aasm policy`](cli/policy.md) — the full policy command group
  (`validate`, `apply`, `simulate`, `history`, …).
