# Multi-Document Policy Cascade

`PolicyEngine::load_cascade_from_dir(dir)` loads every `*.yaml` file in a
directory and populates the gateway's `scope_index` so each document
cascades by its declared scope (`Global` / `Org(<id>)` / `Team(<id>)` /
`Agent(<id>)`). This unlocks org-scoped, team-scoped, and agent-scoped
policy rules in the runtime evaluation path — a capability that
`load_from_file` (single-document) does not provide.

## When to use

* **Multi-tenant deployments** where each org needs its own deny/allow
  overrides on top of a Global baseline.
* **Team-level guardrails** layered on top of the org's rules
  (e.g. "platform team can use bash, but support cannot").
* **Per-agent escape hatches** for a single high-risk agent that needs
  a narrower allowlist than its team's default.

Single-policy deployments should continue using `load_from_file` — the
cascade adds zero value when there's only one document.

## Directory layout

```
policies/
├── 000-global-allow-all.yaml      # scope: global (or omitted)
├── 100-org-acme-deny-bash.yaml    # spec.scope: org:acme
├── 200-team-platform.yaml         # spec.scope: team:platform
└── 300-agent-research-bot.yaml    # spec.scope: agent:<UUID>
```

Filename prefixes are convention only — the loader sorts alphabetically
so the cascade order is deterministic across filesystems. Use numeric
prefixes to make precedence visually obvious.

## Scope field placement (gotcha)

When using the envelope format (`apiVersion` / `kind` / `metadata` /
`spec`), the `scope:` field MUST live inside `spec:`, not at the outer
envelope level:

```yaml
# CORRECT — scope inside spec
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: org-acme-deny-bash
spec:
  scope: org:acme
  tools:
    bash:
      allow: false

# WRONG — scope at envelope level is SILENTLY IGNORED
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: org-acme-deny-bash
scope: org:acme         # ← will be ignored; document defaults to Global
spec:
  tools:
    bash:
      allow: false
```

The validator's envelope parser deserializes `spec`'s value as a
`RawPolicyDocument` — outer-level keys outside the envelope frame are
silently dropped. Always put `scope:` inside `spec:`.

## How the cascade is collected

At evaluation time, the gateway walks scopes from broadest to narrowest
for the calling agent's lineage:

1. **Global** — every Global-scoped document.
2. **Org** — documents matching the agent's `lineage.org_id`. The org
   is resolved from `ctx.metadata["org_id"]` (populated by the SDK's
   proto `AgentId.org_id`).
3. **Team** — documents matching the agent's `lineage.team_id`.
4. **Agent** — documents matching the agent's `lineage.agent_id`.

Each level **augments** the cascade — Global rules still apply for
agents in org-acme; the org-acme rules are added on top. The decision
merger (`merge_decisions`) resolves conflicts with narrower scopes
winning (Agent > Team > Org > Global).

## How `org_id` flows from request to cascade

The cascade's filtering by `lineage.org_id` works through two paths:

1. **From request context** — `convert.rs::request_to_core` deposits
   `proto.org_id` into `ctx.metadata["org_id"]`. `PolicyEngine::evaluate`
   reads this first and uses it as the lineage hint. This is the
   primary path.
2. **From registry fallback** — when `ctx.metadata["org_id"]` is empty
   (e.g. for traffic that doesn't go through the SDK's identity
   plumbing), the engine falls back to `registry.lineage(agent_id)`.

The primary path is what makes `scope: org:<id>` work end-to-end: every
SDK call that populates `AgentId.org_id` lands in the right org's
cascade automatically.

## Programmatic loading

For tests or programmatic setups that don't use a directory:

```rust
use aa_gateway::PolicyEngine;
use tokio::sync::broadcast;

let (alert_tx, _) = broadcast::channel(64);
let engine = PolicyEngine::load_cascade_from_dir(
    std::path::Path::new("/etc/aa-gateway/policies/"),
    alert_tx,
)?;
```

The loader returns the same `PolicyEngine` type as `load_from_file`,
so it drops into existing service wiring without code changes.

## Caveats

* **No filesystem watcher** — the cascade is static at load. Hot-reload
  across multiple files is a separate concern; restart the gateway to
  pick up changes.
* **First Global doc supplies budget config** — alphabetical order
  determines which Global document's `budget:` block sets daily /
  monthly limits and `data.sensitive_patterns`. If two Global docs
  disagree on budget, the alphabetically-first one wins.
* **Parse failures abort the whole load** — partial loads would be a
  worse failure mode than the loud abort; the caller gets a
  `PolicyParseError` for the first bad file.

## Related

* AAASM-2008 — Org-tier isolation (closes the audit / topology /
  credential surfaces; deferred the policy-scope half to this ticket).
* `aa-gateway/tests/cascade_merge_test.rs` — pure-logic unit tests of
  the cascade evaluator (independent of the loader).
* `aa-integration-tests/tests/e2e_org_isolation.rs::st_org_4_*` — the
  E2E test that exercises this loader against a real gateway.
