# Team budgets and cost

**Goal.** Put a hard spend cap on what an agent (and a team) can burn on model
calls, so a runaway planning loop cannot run up an unbounded bill — and watch
spend accumulate against that cap.

## How budgets work

The gateway tracks per-agent and per-team spend and evaluates it on every
governed model call. Budgets are declared in the `budget` section of a policy.
These are the real fields the gateway parses:

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: research-budget
  version: "1.0.0"
spec:
  budget:
    daily_limit_usd: 25.0          # per-agent cap, resets each day
    monthly_limit_usd: 400.0       # per-agent cap, resets each month
    org_daily_limit_usd: 100.0     # organisation-wide daily cap
    org_monthly_limit_usd: 2000.0  # organisation-wide monthly cap
    timezone: "Asia/Taipei"        # IANA tz for the reset boundary (default UTC)
    action_on_exceed: deny         # "deny" (default) or "suspend"
    window: "1h"                   # optional sub-day rollover window (humantime)
```

| Field | Meaning |
|---|---|
| `daily_limit_usd` / `monthly_limit_usd` | Per-agent spend caps. Omit for no limit. |
| `org_daily_limit_usd` / `org_monthly_limit_usd` | Organisation-wide caps, enforced independently of the per-agent caps. |
| `timezone` | IANA timezone that defines the daily/monthly reset boundary. Defaults to UTC. |
| `action_on_exceed` | What happens when the cap is hit: `deny` blocks further spend (default), `suspend` suspends the agent. |
| `window` | Optional sub-day rollover (e.g. `"5s"`, `"30m"`, `"1h30m"`). When absent, spend rolls over at the calendar-day boundary. |

## Step 1 — Validate and apply the budget policy

```console
$ aasm policy validate research-budget.yaml
Policy is valid: research-budget.yaml

$ aasm policy apply research-budget.yaml --applied-by alice@example.com
```

`policy apply` saves the policy to version history (see
`aasm policy history` / `aasm policy rollback`), so a budget change is auditable
and reversible.

## Step 2 — Watch spend against the cap

`aasm cost summary` reports spend for the current period. By default it shows
today; pass `--period month` for the month, and `--group-by agent` to break it
down per agent:

```console
$ aasm cost summary --period today
$ aasm cost summary --period month --group-by agent
```

Each command takes `--output json|yaml` for scripting.

To see where spend is heading, `aasm cost forecast` projects the month from the
current daily rate:

```console
$ aasm cost forecast
```

The fleet-level `aasm status` view also surfaces a budget block at a glance:

```text
BUDGET STATUS
─────────────
  Daily spend : $-- (no limit set)
  Date:           --
  (no per-agent data)
```

(The example above is from a fresh gateway with no budget applied and no spend
yet — once a budget policy is applied and agents start spending, the daily spend
and per-agent rows populate.)

## Step 3 — See budgets in topology

`aasm topology team <team-id>` lists every agent in a team; add `--show-budget`
to include each agent's governance/budget posture in the tree:

```console
$ aasm topology team research --show-budget
```

## What happens at the cap

When an agent reaches its `daily_limit_usd` (or the org cap), the gateway
applies `action_on_exceed`:

- `deny` — the offending model call is denied and audited. The agent keeps
  running but cannot spend until the window resets.
- `suspend` — the agent is suspended (you can later `aasm agent resume <id>`).

Either way the decision lands in the audit log, so cost overruns are
accountable after the fact, not just blocked in the moment.

## Result

The team now has enforceable per-agent and organisation-wide spend caps with a
defined reset boundary and a clear over-budget action, plus CLI views to track
actual spend and forecast the month.
