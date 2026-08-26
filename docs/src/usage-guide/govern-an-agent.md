# Govern an agent end-to-end

**Goal.** Take a real AI dev tool on your machine — Claude Code, Codex, Copilot,
or Windsurf — and launch it so that everything it does runs through Agent
Assembly governance: it is registered with the gateway, tagged to a team and
trace, and routed through the proxy so its tool-calls and network requests are
policy-checked and audited.

> **This guide does not work on a crates.io `aasm`.** `aasm tools` and `aasm run`
> are developer-only commands: `.ci/strip-for-publish.sh` removes them in
> `release.yml`'s `publish-crates` job, so they are absent from
> `cargo install aasm` and present everywhere else — a source build, the GitHub
> Release tarballs, the `curl` installer and the Homebrew formula. See
> [CLI overview → developer-only commands](../cli/overview.md#command-groups).
>
> **There is a newer path for dev tools.** The lifecycle described here — detect,
> wire up, launch — has been superseded for AI dev tools by
> [`aasm integrations`](../cli/integrations.md), which adds plan, receipt,
> verify, drift/repair and remove, and reports an evidence-backed
> [protection level](../devtools/protection-levels.md) instead of a static
> governance tier. `aasm integrations` is stripped on crates.io too. This guide is
> retained because `aasm run` is still how a governed session is launched.

## Prerequisites

- The `aasm` binary built (`cargo build -p aa-cli`; the binary is at
  `./target/debug/aasm`).
- The gateway binary on `PATH` for the `aasm start` helper
  (`cargo build -p aa-gateway --bin aa-gateway`).
- At least one supported AI dev tool installed.

## Step 1 — See which tools Agent Assembly can govern

`aasm` discovers the AI dev tools already installed on the system and reports the
**governance level** it can apply to each. This is a real probe of the machine,
not a static list:

```console
$ aasm tools list
+---------------+---------+---------------------------------------------------------+------------------+
| TOOL          | VERSION | PATH                                                    | GOVERNANCE LEVEL |
+======================================================================================================+
| ClaudeCode    | 2.1.220 | /opt/homebrew/bin/claude                                | L2Enforce        |
|---------------+---------+---------------------------------------------------------+------------------|
| Codex         | 0.144.6 | /opt/homebrew/bin/codex                                 | L2Enforce        |
|---------------+---------+---------------------------------------------------------+------------------|
| GitHubCopilot | 1.388.0 | /Users/you/.vscode/extensions/github.copilot-1.388.0    | L2Enforce        |
+---------------+---------+---------------------------------------------------------+------------------+
```

The **governance level** is each adapter's *static, self-declared* ceiling —
what it says it could achieve for that tool, not what is currently in force.
`L2Enforce` is the highest level any shipped adapter declares; `L3Native` is
defined in the [L0–L3 matrix](../governance/capability-matrix.md) but no adapter
returns it today, and `aa-devtool-saas` is the only one capped at `L1Observe`.

> **A level here is not a protection claim.** It is a declaration, not evidence:
> nothing about this column says traffic was inspected. For an evidence-backed
> answer to "is this tool actually protected right now, and how do you know",
> use [`aasm integrations status <tool>`](../cli/integrations.md), which reports
> the [protection ladder](../devtools/protection-levels.md) derived from
> observations rather than a self-declared tier.

## Step 2 — Start the gateway

The gateway is the decision engine every governed action is checked against.
For a local, in-process control plane:

```console
$ aasm start --mode local --port 7391
```

This serves the HTTP control-plane API and the dashboard on
`http://127.0.0.1:7391` with a local SQLite store. You can confirm it is up:

```console
$ aasm --api-url http://127.0.0.1:7391 status
Agent Assembly Status
─────────────────────────────────────
  Mode:      local
  Gateway:   http://127.0.0.1:7391
  Storage:   sqlite
  Version:   0.0.1-beta.4
  Uptime:    2m 24s
  Health:    ✓ ok
─────────────────────────────────────

STORAGE
───────
  Backend:     sqlite
  Path:        /Users/you/.aasm/local.db
  DB Health:   ✓ ok  (0ms)
  Rows:        audit_events: 0 hot
               agents: 0  |  policies: 0
```

> The fleet starts empty (`agents: 0`) — nothing is governed until you launch a
> tool under `aasm run` in the next step.

## Step 3 — Write the policy the session runs under

Note the `policies: 0` in the status above. A running gateway is a decision
engine with nothing to decide from, and `aasm run` refuses to launch a tool in
that state: an absent policy is not permission. Write one first.

```console
$ cat > ~/.aasm/policy.yaml << 'EOF'
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: research-team
spec:
  tools:
    "*":
      allow: false
    read_file:
      allow: true
  network:
    allowlist:
      - api.anthropic.com
EOF
$ aasm policy validate ~/.aasm/policy.yaml
Policy is valid: /Users/you/.aasm/policy.yaml
```

`~/.aasm/policy.yaml` is one of the locations `aasm run` searches, along with
`--policy <FILE>` and `$AA_POLICY` — the same order `aasm gateway start` uses.
The full order and the four states a resolution can land in (two of which
refuse) are in [Policy YAML Reference → Where a governed launch finds this
file](../policy-reference.md#where-a-governed-launch-finds-this-file).

> **Applying a policy to the gateway is a different action.**
> `aasm policy apply` uploads a document to the gateway's version history; it
> writes nothing to the locations `aasm run` searches. Run both if you want the
> same document in both places — a policy can be live on the gateway and still
> leave the next `aasm run` unconfigured.

## Step 4 — Launch the tool under governance

`aasm run <tool>` is the heart of this scenario. It assigns the session an
**agent identity**, a **team**, and a **trace id** for lineage tracking, wires
in the proxy, and then execs the real tool. Before running it for real, use
`--dry-run` to see exactly what governance wiring will be applied — nothing is
launched:

```console
$ aasm run claude --team-id research --agent-id research-bot-01 --dry-run
policy=enforced — 2 rule(s) from /Users/you/.aasm/policy.yaml
--- aasm run dry-run ---
agent_id:    research-bot-01
trace_id:    dry-run-daa9d73a-f2fc-4977-9d00-50f4c4025fa9
session_id:  dry-run-0d7a0c16-25b2-456b-84e8-b7907fa963d1

--- policy ---
state:  enforced
source: /Users/you/.aasm/policy.yaml
detail: enforced — 2 rule(s) from /Users/you/.aasm/policy.yaml

--- managed settings ---
<dry-run: managed settings not generated>

--- launch command ---
claude

--- environment ---
# values are withheld unless the variable is on the preview allowlist: <set> = present, value withheld; <set:empty> = present and empty; ***MASKED*** = present, name says credential
AA_AGENT_ID=research-bot-01
AA_REGISTRATION_ID=dry-run-2b00ef56-3f35-4ef9-8164-ea899dfe90aa
AA_SESSION_ID=dry-run-0d7a0c16-25b2-456b-84e8-b7907fa963d1
AA_TEAM_ID=research
AA_TRACE_ID=dry-run-daa9d73a-f2fc-4977-9d00-50f4c4025fa9
AI_AGENT=<set>
ANTHROPIC_BASE_URL=https://gateway.internal<path:1 segment>
CLAUDECODE=<set>
CLICKUP_API_TOKEN=***MASKED***
GITHUB_TOKEN=***MASKED***
HTTPS_PROXY=http://127.0.0.1:8080
JIRA_API_TOKEN=***MASKED***
NODE_EXTRA_CA_CERTS=/Users/you/.aasm/ca.pem
SLACK_BOT_TOKEN=***MASKED***
...
```

Notice five things that are doing real work:

- The `--- policy ---` receipt names which of the four effective-policy states
  this launch resolved to, and from which file. It is printed for all four,
  including the two that refuse: a preview whose whole job is to say what a live
  run would do has to show you `state: unconfigured` rather than omit the
  section and let "no policy at all" look like a formatting quirk. On a state
  that would refuse, the preview warns and still completes.
- The `AA_*` environment variables (`AA_AGENT_ID`, `AA_TEAM_ID`, `AA_TRACE_ID`,
  `AA_REGISTRATION_ID`, `AA_SESSION_ID`) are injected so the launched tool's
  events carry identity and lineage back to the gateway.
- Environment **values are withheld by default**. The preview lists every
  variable the child will inherit, but prints a value only for the small
  reviewed set an operator needs in order to verify a governed launch — the
  `AA_*` identity and lineage variables, the proxy route, the CA, and the model
  selection. Everything else shows as `<set>` (present, value withheld) or
  `<set:empty>` (present and empty). The legend is printed in the output itself.

  This is deliberately deny-by-default rather than "mask the ones that look
  secret". Masking by *name* cannot see a secret in a blandly-named variable:
  a variable whose value is an encoded snapshot of your whole environment
  matches no credential pattern, so it used to be printed in full — including
  the tokens the same output had masked by name. Withholding unless a name was
  reviewed has no such gap.
- Variables whose **name** says credential — API tokens, PATs — additionally
  show as `***MASKED***` rather than a bare `<set>`, so the receipt still tells
  you that Agent Assembly recognised the variable as secret-bearing.
- URL values are shown as **scheme, host and port only**, with the path
  reported as a segment count (`<path:1 segment>`). A URL can carry a
  credential in its userinfo, path, query or fragment — proxy URLs in
  particular often do — so the preview keeps the part that answers "where does
  this traffic go" and discards the rest.

When you drop `--dry-run`, the same wiring is applied for real and the tool
starts. Useful flags:

| Flag | Effect |
|---|---|
| `--team-id <id>` | Tag the session to a team (drives team budgets and topology). |
| `--governance-level <level>` | Override the level Agent Assembly applies. |
| `--enforcement-mode observe` (or `--observe`) | Compute and audit policy decisions but never block — a shadow run. |
| `--enforcement-mode enforce` | Default — deny blocks, redact strips. |
| `--policy <FILE>` | Use this policy for the session. When given it is the entire search — no fallback to `$AA_POLICY` or the well-known locations. |
| `--no-proxy` | Skip proxy injection (not recommended for governed environments). |
| `--root-agent <id>` | Record a parent for multi-agent lineage. |

The `--enforcement-mode` distinction matters when rolling governance out: start
with `--observe` to see what *would* be blocked without breaking the agent, then
switch to `enforce` once the policy is right. Neither mode waives the policy
requirement: `--observe` chooses what happens to a decision, and an unconfigured
launch has nothing to decide from, so it is refused either way.

## Step 5 — Observe the governed agent

Once the tool is running under `aasm run`, the registered agent appears in the
fleet and its actions flow into the audit log. You inspect it with:

```console
$ aasm agent list                 # all registered agents
$ aasm agent inspect <agent-id>   # one agent in detail
$ aasm topology team research     # the whole team
$ aasm status                     # fleet health at a glance
```

and watch its decisions live via the dashboard — see
[Observe in the dashboard](observe-in-dashboard.md).

## Result

You now have a real AI tool running with a stable governed identity, its
tool-calls and outbound requests *routed* to the gateway for an allow/deny
decision, secrets scrubbed from the recorded environment, and an audit trail
keyed to the agent, team, and trace you assigned in Step 4.

**Routing is not proof.** Everything above describes configuration that was
applied, which is not evidence that anything inspected the traffic — and a tool
started directly, outside `aasm run`, inherits none of this wiring. To turn
"configured" into a measured claim, use the
[integration lifecycle](../cli/integrations.md): `aasm integrations verify
<tool>` runs an adjudicated exercise on the model-bound path and exits `0` only
when the protected path was actually exercised *and* the outcome was protective.
Its [limitations page](../devtools/limitations.md) states what remains
unmeasured.
