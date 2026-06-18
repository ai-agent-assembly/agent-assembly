# Sandbox / Dry-Run Mode

> Run any policy **in observe-only mode** for a few days before flipping the switch to live enforcement.

Sandbox mode is the governance analogue of a database transaction ROLLBACK: the gateway evaluates every rule, records every would-be decision in the audit log, and **applies none of them**. The agent proceeds as if no policy were in effect. Once you've reviewed the would-be violations and tuned the policy, you cut over to live `enforce` mode with a one-line change.

The feature is part of the open-source core — not an enterprise add-on.

---

## How it works

Sandbox mode is an **enforcement posture**, not a separate runtime. It only changes what the gateway does *after* a policy decision is computed:

| Decision | Enforce mode (default) | Observe / dry-run mode |
| --- | --- | --- |
| `Allow` | Action proceeds | Action proceeds (identical) |
| `Deny` | Action blocked; error returned | Action proceeds; `dry_run: true` shadow event written to the audit log |
| `Redact` | Payload sanitised | Unredacted payload forwarded; shadow event written |
| `RequiresApproval` | Action halts pending review | Action proceeds; shadow event written |

Every shadow event carries the full decision context: which rule matched (`shadow_decision`), what the rejection reason would have been (`shadow_reason`), and a `dry_run: true` flag the audit consumer can filter on.

---

## Quick start — 5 steps

```bash
# 1. Author a policy (the section-based schema the gateway loads)
cat > coding-team-sandbox.yaml << 'EOF'
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: coding-team-sandbox
spec:
  # Block destructive shell tooling.
  tools:
    bash:
      allow: false
  # Detect leaked AWS / GitHub credentials and redact them.
  data:
    credential_action: redact_only
    sensitive_patterns:
      - "(AKIA|ghp_)[A-Za-z0-9]+"
EOF

# 2. Apply the policy
aasm policy apply --file coding-team-sandbox.yaml

# 3. Run an agent under observe-mode governance (posture is a runtime flag,
#    not a policy-document field — see "Policy configuration" below)
aasm run --observe claude --workspace .

# 4. After a few days, review what would have been blocked
aasm audit list --dry-run-only --since 7d

# 5. Confident the policy is right? Drop --observe to enforce for real.
aasm run claude --workspace .
```

---

## Policy configuration

The **policy document** describes *what* the rules are using the section-based
schema (`network` / `tools` / `data` / `budget` / `schedule` / `capabilities`).
It does **not** carry the enforcement posture — observe vs enforce is a
**per-agent runtime setting**, so the same policy can run in observe mode for
one agent and live `enforce` for the rest.

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: my-policy
spec:
  tools:
    bash:
      allow: false
  data:
    credential_action: redact_only
    sensitive_patterns:
      - "(AKIA|ghp_)[A-Za-z0-9]+"
```

The enforcement posture is chosen where the agent is launched or registered:

- **CLI** — `aasm run --observe <tool>` (or `--enforcement-mode observe`) for the
  duration of that session.
- **SDK** — pass `enforcement_mode="observe"` (Python / Go) or
  `enforcementMode: "observe"` (Node.js) at `initAssembly` / agent registration.

Resolution order (highest priority first):

1. **Per-agent override** — `enforcement_mode` on the agent's `RegisterAgent` RPC payload (set via the CLI flag or SDK option above).
2. **Server-wide default** — `enforce`.

When no override is supplied, the gateway applies its server-side `enforce`
default — the pre-feature behaviour.

---

## CLI reference

### `aasm run --observe`

Launches a managed AI dev tool with observe-mode governance for the duration of the session.

```bash
# Boolean shorthand — most common case
aasm run --observe claude --workspace .

# Explicit form — interchangeable with the above
aasm run --enforcement-mode observe claude --workspace .

# Disabled mode — only valid in hermetic test environments
aasm run --enforcement-mode disabled codex --workspace .

# Combine with --dry-run to preview the launch without executing the tool
aasm run --observe --dry-run claude --workspace .
```

When observe mode is active, a one-time banner prints to stderr ahead of any tool output:

```
⚠️  [AAASM] Running in sandbox/observe mode.
    Policy decisions are recorded but NOT enforced.
    Review captured events: aa audit list --dry-run-only
```

The child process inherits `AA_ENFORCEMENT_MODE=observe` in its environment so tools that env-sniff (or downstream wrappers) can surface their own observe-mode badge.

`--observe` and `--enforcement-mode` are **mutually exclusive** — passing both fails fast at clap-parse time.

### `aasm audit list --dry-run-only`

Filters the audit log to shadow events only:

```bash
# Show shadow events from the last 24h
aasm audit list --dry-run-only --since 24h

# Compose with other filters
aasm audit list --dry-run-only --since 7d --agent "codex-*"

# Machine-readable output for CI gates
aasm audit list --dry-run-only --format json
```

The flag is **exclusive**: by default `aasm audit list` HIDES shadow events so operators don't see them mixed with live decisions; `--dry-run-only` flips that to show ONLY shadow events.

---

## SDK usage

All three SDKs expose the same posture surface. Pass an `enforcement_mode` (Python / Go) or `enforcementMode` (Node.js) at agent registration:

### Python

```python
from agent_assembly import init_assembly

ctx = init_assembly(
    gateway_url="http://localhost:8080",
    api_key="...",
    agent_id="experimental-agent-001",
    enforcement_mode="observe",   # "enforce" | "observe" | "disabled"
)
```

The parameter is keyword-only; the type is `Literal["enforce", "observe", "disabled"]`. Omitting it preserves the pre-feature wire shape (the gateway applies its server-side `enforce` default).

### Node.js / TypeScript

```typescript
import { initAssembly, type EnforcementMode } from "@agent-assembly/sdk";

const ctx = await initAssembly({
  gatewayUrl: "http://localhost:8080",
  apiKey: "...",
  agentId: "experimental-agent-001",
  enforcementMode: "observe",   // 'enforce' | 'observe' | 'disabled'
});
```

The `EnforcementMode` union narrows at compile time; runtime validation catches typos from JS / JSON-config / dynamic-input callers with a `RangeError`.

### Go

```go
import "github.com/agent-assembly/go-sdk/assembly"

a, err := assembly.Init(ctx,
    assembly.WithGatewayURL("http://localhost:8080"),
    assembly.WithAPIKey("..."),
    assembly.WithSelfAgentID("experimental-agent-001"),
    assembly.WithEnforcementMode(assembly.EnforcementModeObserve),
)
```

`assembly.EnforcementMode` is a string-typed alias; the empty zero value omits the field from the registration body, preserving pre-feature wire shape.

---

## CI integration — the policy-regression gate

A common observe-mode use case: gate every PR on "would my policy change block any existing agent workflow?"

```yaml
# .github/workflows/policy-regression.yml
jobs:
  policy-regression:
    steps:
      - name: Run agent under observe-mode governance
        run: aasm run --observe codex -- codex "refactor src/auth.py"

      - name: Fail the PR on any would-be deny
        run: |
          BLOCKS=$(aasm audit list --dry-run-only --format json \
                   | jq '[.[] | select(.shadow_decision == "deny")] | length')
          if [ "$BLOCKS" -gt 0 ]; then
            echo "Policy regression: $BLOCKS actions would be blocked"
            aasm audit list --dry-run-only --format table
            exit 1
          fi
```

The exclusive-filter semantic of `--dry-run-only` means this gate doesn't pick up unrelated live-enforcement events from other agents on the same gateway.

---

## Dashboard

The dashboard exposes a `SandboxSummaryCard` component that renders the per-policy observe-mode aggregates:

```
┌─ SANDBOX SUMMARY ────────────────────────────────┐
│ coding-team-sandbox (last 24h)                    │
│                                                   │
│  47        12         3                           │
│  Would-be  Would-be   Would-be                    │
│  denies    redactions pending approvals           │
│                                                   │
│  Top matched rule: block-bash-rm-rf (31×)         │
│                                                   │
│  [View all events]  [Export CSV]  [Enable live →] │
└───────────────────────────────────────────────────┘
```

The amber colour is intentional — it visually contrasts with the dashboard's red (live-deny) and green (live-allow) tokens so an operator can tell at a glance whether they're looking at observe-mode aggregates or live enforcement data.

> **Status (2026-05):** the card primitive is shipped (AAASM-1563). The full integration — wiring it into Policy detail, the audit-log toggle, the amber row badge, and the "Enable live enforcement" action — is tracked under [AAASM-1911](https://lightning-dust-mite.atlassian.net/browse/AAASM-1911) and depends on `aa-api` surface changes that aren't in this release.

---

## Graduating to live enforcement

Once you've reviewed the shadow events and tuned the policy:

1. **Inspect the most-common would-be violations**:
   ```bash
   aasm audit list --dry-run-only --since 7d --format json \
     | jq 'group_by(.shadow_decision) | map({decision: .[0].shadow_decision, count: length})'
   ```
2. **Adjust the policy** — tighten matchers that fired too eagerly, relax ones that blocked legitimate work.
3. **Re-apply and re-run in observe mode** for another short window to confirm the tuned policy behaves as expected.
4. **Flip to enforce** — drop the observe flag where the agent is launched:
   ```bash
   # was: aasm run --observe claude --workspace .
   aasm run claude --workspace .
   ```

The cutover takes effect from the agent's next registration onward — the policy document itself is unchanged. Already-in-flight actions evaluated under the observe session keep their original posture.

---

## FAQ

**Does observe mode affect performance?**
No measurable difference. The rule pipeline runs identically; the only added work is writing the shadow audit event when a non-`Allow` decision would have fired. That's the same audit-write path live enforcement already uses, so the per-request cost is dominated by the rule evaluation itself.

**Are redacted payloads ever stored in observe mode?**
No. The `redact` decision in observe mode forwards the **unredacted** payload to the agent (that's the whole point — "what would have happened if we'd enforced"). The shadow audit event records that a redact rule matched, but neither the would-be redacted version nor the raw payload is persisted as a separate artefact. The audit pipeline's existing PII-scanner pass still applies before any event is written.

**Can I set observe mode per-agent without changing the policy?**
Yes — the posture is always per-agent, never baked into the policy document:
1. CLI: `aasm run --observe <tool>` for the duration of that session.
2. SDK: pass `enforcement_mode="observe"` (Python / Go) or `enforcementMode: "observe"` (Node.js) at `initAssembly`.

The per-agent posture always wins over the server-wide `enforce` default.

**What happens to an agent that's mid-action when I flip from observe to enforce?**
The action that's already through `CheckAction` keeps its observe-mode disposition (allowed). The very next `CheckAction` call sees the new posture and starts enforcing. There's no in-flight rollback.

**Does the SDK have any guard against accidentally registering in observe mode?**
The SDK doesn't second-guess the operator — observe mode is a deliberate posture. What the SDK does is:
- Reject typos (e.g. `"obesrve"`) with a clear error at `init` time
- Default to "no opinion" (omits the field from the registration body) so a pre-feature SDK call gets the gateway's server-side `enforce` default — only operators who explicitly opt in get observe mode

**Can I use observe mode in production for a long-running agent?**
That's the recommended pattern for new policies — run them in observe mode for a week, review the shadow events, then cut over. The audit log retention follows your normal retention policy, so the shadow events are queryable for as long as live events.

---

## See also

- [L0–L3 Capability Matrix](../governance/capability-matrix.md) — sandbox mode applies at all governance tiers
- [System architecture](../architecture/system-architecture.md) — where the policy evaluator sits in the request pipeline
