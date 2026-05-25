# Tool Execution Sandbox — Network Egress

Agent Assembly's Tool Execution Sandbox enforces a network allowlist on
outbound traffic from sandboxed tools: when a tool tries to CONNECT to
a host that is not on the allowlist, the proxy returns HTTP 403 before
any upstream dial and emits an audit event recording the blocked egress.
This is the **network half** of spec highlight ④ (Tool Execution
Sandbox); the filesystem-isolation half is tracked under
[AAASM-1965](https://lightning-dust-mite.atlassian.net/browse/AAASM-1965).

## Configuration

The allowlist is configured on the `aa-proxy` process via the
`AA_PROXY_NETWORK_ALLOWLIST` environment variable. Comma-separated;
empty means "no allowlist filter" (the pre-AAASM-1943 default-open
posture is preserved when the variable is unset).

```bash
export AA_PROXY_NETWORK_ALLOWLIST='api.openai.com,*.anthropic.com,*.googleapis.com'
aa-proxy run
```

Equivalent policy-DSL form (operator-facing documentation; the proxy
reads from the env var today, with policy-DSL → proxy-config sync
tracked under the AAASM-1232 closeout matrix):

```yaml
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: prod-egress
  version: "1.0.0"
spec:
  network:
    allowlist:
      - api.openai.com
      - "*.anthropic.com"
      - "*.googleapis.com"
```

## Pattern grammar

The same matcher (`aa_core::policy::is_host_allowed_by_egress_allowlist`)
is used by the proxy enforcement path and the gateway policy DSL. The
grammar is intentionally narrow:

| Pattern | Matches | Does NOT match |
|---|---|---|
| `api.openai.com` (exact) | `api.openai.com` (case-insensitive) | `chat.openai.com`, `openai.com`, `attackerapi.openai.com` |
| `*.openai.com` (leftmost-label wildcard) | `api.openai.com`, `chat.openai.com`, `a.b.openai.com` | `openai.com` (bare), `evil.openai.com.attacker.net` (suffix attack) |
| `*` (universal — escape hatch) | every host | — |

**No mid-label `*`, no character classes, no full POSIX glob.** Allowlist
patterns that look more permissive than they are have historically been
the source of egress-rule misconfigurations; the narrow grammar lets
operators reason about every pattern at a glance.

The attacker-crafted-suffix case (`evil.openai.com.attacker.net` against
`*.openai.com`) is a classic confusion attack: the attacker hopes a
permissive glob would match. The narrow grammar rejects it.

## Audit events

Both the allow and deny CONNECT paths emit `PipelineEvent::Audit`
events on the proxy's broadcast channel. The deny path additionally
returns `HTTP 403 Forbidden\r\nContent-Length: 0\r\n\r\n` to the
sandboxed tool, which sees a connection refusal at its language-level
HTTP client.

Audit reviewers can correlate blocked-egress events to source tools
via the existing `aasm logs` / `aasm audit list` tooling. The audit
payload carries the target host so operators can spot patterns (e.g.
a tool repeatedly trying to reach a c2 server).

```bash
# Recent denied CONNECT attempts
aasm logs --since 1h --grep "denied by network allowlist"

# Compliance export of all network-policy violations
aasm audit compliance-export \
  --input      /var/lib/aa-gateway/audit/session-<hex>.jsonl \
  --event-type PolicyViolation \
  --format     jsonl \
  --output-file ./network-violations.jsonl
```

## What this does NOT cover (deferred to AAASM-1965)

This page documents the network-egress half of spec highlight ④. The
filesystem-isolation half ("`cat /etc/passwd` from inside a sandboxed
tool blocked / redacted") requires a WASM/WASI sandbox runtime that
doesn't yet exist in the repo. Filed under
[AAASM-1965](https://lightning-dust-mite.atlassian.net/browse/AAASM-1965)
as a Story-point-8 follow-up:

- `aa-wasm` extended with `wasmtime` + WASI preview 1 host handlers.
- `ToolRegistry` distinguishing WASM-runnable tools from native /
  shell tools.
- Filesystem allowlist enforcement returning `EACCES` for paths
  outside the sandbox root.
- E2E tests for the `cat /etc/passwd` denial path.

The ST-W ignored placeholder in
`aa-integration-tests/tests/e2e_tool_sandbox.rs::st_w_1_filesystem_isolation_for_sandboxed_tools`
contains the exact assertion plan the follow-up will fill in.
