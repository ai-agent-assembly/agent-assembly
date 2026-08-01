# Onboarding a Developer Integration

This is the path from *nothing installed* to *a Claude Code integration whose
protection state you can read and act on*, using the commands that exist today
and describing what they actually do.

It is deliberately not a marketing walkthrough. Three of the steps below end in a
state that is **weaker than you might expect**, and each is called out where you
will hit it rather than in a footnote:

* A fully installed integration still **refuses to launch anything** until a
  policy exists — an absent policy is not permission. See
  [Step 5](#step-5--write-the-policy-the-session-will-run-under).
* `aasm integrations verify claude-code` **exits `6` whenever the protected path
  was never exercised and adjudicated** — see
  [Step 7](#step-7--verify-and-the-exit-6-that-means-not-measured).
* `Gateway Protected` **is** reachable on a default build once that exercise has
  happened (AAASM-5300) — but a file existing is still never enough on its own.

> **Scope.** Claude Code on macOS is the only natively migrated integration
> ([AAASM-5281](https://lightning-dust-mite.atlassian.net/browse/AAASM-5281)).
> Codex, GitHub Copilot and Windsurf Cascade are carried by `LegacyAdapterShim`:
> they can be discovered, planned and reported on, but an apply is refused rather
> than reported as a success that performed nothing
> ([`aasm integrations` CLI](cli.md)).

---

## Before you start

| Requirement | Why | How to check |
|---|---|---|
| macOS | The MVP platform ([product brief](product-brief.md) §10). | — |
| Claude Code **≥ 1.0.0** | The adapter's `MIN_VERSION`. A lower version is reported as *absent*, not as partially supported, so nothing is written for it (`aa-devtool-claude-code/src/lib.rs`). | `claude --version` |
| `aasm` **from any channel except crates.io** | The reference client for the [Developer Integration API](developer-integration-api.md). `.ci/strip-for-publish.sh` removes `aasm integrations` (AAASM-5309) in `release.yml`'s `publish-crates` job only, so `cargo install aasm` does not have it — and that `aa-runtime` never binds the socket either. A `brew` install, the GitHub Release tarballs, the `curl` installer and a source build (`cargo build -p aa-cli`) all have it. | `aasm integrations --help` (not `aasm --version`, which succeeds either way) |
| An Agent Assembly runtime | Every lifecycle operation runs inside `aa-runtime`. There is no in-process fallback. | see below |

### The Developer Integration API is opt-in

`aa-runtime` does **not** serve the DI-API unless it is asked to. The surface is
gated on `AA_DEVINT_ENABLED`, read at startup and **off by default**
(`aa-runtime/src/config.rs`). A runtime started without it comes up perfectly
healthy and simply has no integrations socket — which is why the CLI's error text
names the variable rather than telling you to "check the logs".

You do not normally set it yourself. **When no runtime is listening, `aasm`
starts one with `AA_DEVINT_ENABLED=1` set**, says so on `stderr`, and waits for
the socket to bind:

```console
$ aasm integrations list
Starting Agent Assembly runtime…
Agent Assembly core 0.0.1-rc.6 (DI-API v2)
```

Pass `--no-autostart` — it is global across all `integrations` subcommands — to
turn a missing runtime into **exit `7`** instead. Use it in CI, where leaving a
daemon behind is worse than failing. If you start the runtime yourself, start it
with `AA_DEVINT_ENABLED=1`.

Notices, prompts and errors go to `stderr`; reports go to `stdout`. So
`aasm integrations status claude-code --output json | jq` stays parseable even on
the run that had to start the runtime first.

---

## Step 1 — Discover what is here

```console
$ aasm integrations list
TOOL             VERSION      COMPAT       STATE          PROTECTION
claude-code      2.1.220      compatible   ladder         detected_not_integrated
codex            0.144.6      compatible   ladder         detected_not_integrated
github-copilot   -            unknown      ladder         not_installed
windsurf-cascade -            unknown      ladder         not_installed
```

`--capabilities` expands each tool to its declared mechanisms rather than the
summary row. Nothing here mutates anything.

## Step 2 — Read the plan before anything is written

```console
$ aasm integrations plan claude-code --profile recommended --scope user
```

`plan` is a dry run that mutates nothing, and it is the honest place to decide
whether you want this. It names every file, key and artifact an install would
touch — and it also names the bypasses this integration **cannot** observe, so
you never have to read the absence of a finding as the absence of a bypass.

### Choose the scope; it is never inferred

`--scope` defaults to `user`.

| Scope | Writes | Notes |
|---|---|---|
| `user` | `$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json` | The default. |
| `project` | `<cwd>/.claude/settings.json` | Checked in and shared. Selectable, never a default. |
| `managed` | `/Library/Application Support/ClaudeCode/managed-settings.json` | Administrator-owned. Opt-in only, via `--install-managed-settings`. See below. |

A `.claude/` directory in your working directory never redirects a `user`-scoped
install. This is deliberate: the underlying `apply` resolver *does* prefer a
project file whenever one exists, and a lifecycle whose destination depends on
where you happened to `cd` cannot write a receipt it can later compare drift
against or restore from (AAASM-5276 condition **C2**;
`aa-devtool-claude-code/src/scope.rs`).

`--scope managed` on its own is **refused**, and points you at the flag that
names what it does: `--install-managed-settings`. That is deliberate — `managed`
reads like a third choice alongside `user` and `project`, and nothing about it
says *this will ask for your administrator password*.

```console
$ aasm integrations install claude-code --install-managed-settings
```

This adds **one** privileged step: placing a single file at
`/Library/Application Support/ClaudeCode/managed-settings.json`, owned by root.
`aasm` itself never runs as root. Before you are asked to approve anything, the
plan states the exact path, the exact bytes, the diff against what is already
there, any conflict, and the backup and rollback behaviour. It is the only route
to [`Host Enforced`](protection-levels.md#host-enforced) — and it refuses rather
than merging over a managed-settings file Agent Assembly did not write. Read
[Limitations](limitations.md#the-managed-settings-file-can-be-installed-its-enforcement-is-still-unmeasured)
for what the resulting claim does and does not cover.

## Step 3 — Choose a profile

`--profile` selects what the integration *does about* what it detects. A profile
is what you chose; a **level** is what the system can prove it is currently doing
([Protection levels](protection-levels.md)).

| Profile | `EnforcementMode` | Sensitive-data finding on a model-bound path | Egress | Budget |
|---|---|---|---|---|
| `recommended` *(default)* | `Enforce` | **Redact and proceed.** The match is replaced with a `[REDACTED:<kind>]` placeholder and the request continues. | Policy allowlist enforced at the wire by `aa-proxy`. | Enforced. |
| `strict` | `Enforce` | Redact and proceed **today**. Blocking on a configured high-severity class is _planned_ — see below. | Same enforcement, narrower default allowlist. | Enforced; `Suspend` available. |
| `observe-only` | `Observe` | **Recorded only; the payload is forwarded unchanged.** | Evaluated and audited; nothing blocked. | Tracked, not enforced. |

Three things about this table are load-bearing:

* **`strict` does not yet block on a scanner finding.** The core's policy
  pipeline redacts unconditionally; blocking is _planned_
  ([AAASM-5277](https://lightning-dust-mite.atlassian.net/browse/AAASM-5277),
  [AAASM-5281](https://lightning-dust-mite.atlassian.net/browse/AAASM-5281)).
  Until it lands, `strict` differs from `recommended` on egress, approvals and
  budget only.
* **`observe-only` forwards the secret.** That is correct behaviour for
  `EnforcementMode::Observe`, it was measured in AAASM-5276, and it is why
  `observe-only` is **never** displayed as protection: status says *monitoring*,
  with a standing not-enforcing warning.
* **Org policy clamps your choice.** Profiles merge with the org cascade under
  most-restrictive-wins, so a local profile may tighten and can never loosen.

`EnforcementMode::Disabled` is not reachable from any profile, ever.

## Step 4 — Install

```console
$ aasm integrations install claude-code --profile recommended --scope user
```

The plan is shown and you are asked to confirm. `--yes` is **required** for
non-interactive runs and for `--output json`/`yaml`, which have no way to answer
a prompt — without it the command aborts with exit `9` and changes nothing.
Silence is not consent. `--dry-run` shows the plan and stops, exactly as `plan`
does.

The Claude Code plan applies five steps and offers a sixth
(`aa-devtool-claude-code/src/lifecycle.rs`):

| Step | What it does |
|---|---|
| `managed-settings` | Merges the four Agent Assembly-owned keys — `permissions`, `permissionMode`, `enabledMcpjsonServers`, `disabledMcpjsonServers` — into the settings file for the scope you chose. Every other key is left exactly as it was (`apply.rs`). |
| `proxy-ca` | Copies the proxy's certificate authority to a PEM Agent Assembly owns. **The system trust store is not touched.** |
| `node-extra-ca-certs` | Sets `NODE_EXTRA_CA_CERTS` for every governed launch. **Without this the interception handshake fails and nothing is inspected** — and it fails *silently*, because a proxy that cannot terminate TLS still lets the connection through. This is AAASM-5276 condition **C1**. |
| `proxy-env` | Routes governed launches through the local proxy. |
| `side-channel-scope` | Asks the proxy to inspect `api.anthropic.com` and `*.anthropic.com` for this integration. One headless `claude -p` run was measured producing four upstream requests — two `/v1/messages` POSTs, an MCP-registry GET, and a 130 KB telemetry batch — so scoping to the model endpoint alone would leave real channels unscanned (condition **C5**). `llm_only` stays on, so nothing else on your machine is intercepted. |
| `protection-test` | **Optional.** Sends a synthetic secret down the model path so the core can adjudicate what the provider received. |

Two flags exist because two things must be consented to explicitly:

* `--allow-privileged-host-steps` is **off by default**. A privileged step is
  never implied by a profile, and a plan containing one cannot be applied unless
  it was planned with the flag — the plan is the record of what was consented to.
* `--policy-profile <name>` resolves a policy document by name. The document
  itself never crosses the DI-API boundary; only its id, display name and digest
  do.

**Install is idempotent.** A second install on an unchanged system applies no
additional mutation. If a step fails mid-plan the install is reported as
*partial* — `the install is partial — N step(s) failed` — and you should run
`status`, then `repair` or `remove`. A partial install is never presented as
reduced protection.

## Step 5 — Write the policy the session will run under

Everything so far configured *interception*: what gets seen. A policy is what
decides what to **do** about what is seen, and `aasm run` will not launch
without one. This is the third of the steps that ends somewhere weaker than you
might expect, and it is the one you hit first:

```console
$ aasm run claude
policy=unconfigured — no policy artifact found; a governed launch is refused
error: refusing to launch ungoverned: no effective policy is configured, so this
session would run under no rules at all. An absent policy is not permission.
```

That refusal is the design, not a missing prerequisite nobody mentioned. A
profile from [Step 3](#step-3--choose-a-profile) is a posture — what to do with
a decision — and an install from [Step 4](#step-4--install) is wiring. Neither
is a set of rules, so at this point nothing has said what this agent may do.
`aasm run` treats "nobody has said" as its own state rather than as permission,
and refuses **before** the tool starts, because a `claude` already running under
no policy cannot be governed after the fact.

So write one. The smallest useful policy names the tools you care about:

```console
$ cat > ~/.aasm/policy.yaml << 'EOF'
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: claude-code-local
spec:
  tools:
    "*":
      allow: false
    read_file:
      allow: true
    bash:
      allow: true
      requires_approval_if: "path starts_with \"/etc\""
EOF
$ aasm policy validate ~/.aasm/policy.yaml
Policy is valid: /Users/you/.aasm/policy.yaml
```

**Spell `allow:` out on every tool entry.** A tool that omits it is *denied*, not
allowed — so `bash` above without its `allow: true` would be a flat deny and the
`requires_approval_if` beside it would never be reached. That default is
deliberate (AAASM-3134): a half-written rule or a typo'd key must fail closed.
It does mean a rule can read as an approval gate while behaving as a block —
`validate` does not warn, and the `--dry-run` receipt reports the policy *state*,
not its per-tool decisions, so neither will tell you. Being explicit is the only
check there is.

`~/.aasm/policy.yaml` is one of the locations `aasm run` searches; `--policy
<FILE>` and `$AA_POLICY` are the others, in the same order
[`aasm gateway start`](../cli/gateway.md) uses. The full order, the four states
a resolution can land in, and the two that refuse are in
[Policy YAML Reference → Where a governed launch finds this file](../policy-reference.md#where-a-governed-launch-finds-this-file).

Two of those states are worth knowing before you meet them:

* **A policy with no `tools:` entry is `unconfigured`, not partially enforced.**
  A file containing only a `budget:` still refuses the launch, because a
  dev-tool adapter writes tool permissions into the tool's own settings file and
  has nowhere to put a spend cap. Budgets are enforced by the gateway.
* **A directory is `load_failed`.** `~/.aasm/policies/` is the gateway's
  multi-document cascade; `aasm run` renders one effective document and does not
  merge one. If you drive the gateway from a cascade, point `aasm run` at a
  single file with `--policy`.

If you genuinely want this agent unrestricted, say so — the state is called
`permissive` and it is reached by writing it down, never by leaving the policy
out:

```yaml
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: allow-all
spec:
  tools:
    "*":
      allow: true
```

There is no `--permissive` flag, deliberately: a flag is easy to set without
reading what it turns off. The banner then says `policy=permissive — …` on every
launch, so nobody reading the session's output mistakes it for a governed one.

## Step 6 — Launch through the managed path

```console
$ aasm run claude
policy=enforced — 3 rule(s) from /Users/you/.aasm/policy.yaml
```

The `policy=` banner goes to `stderr` ahead of any tool output, and the resolved
state also reaches the tool as `AA_POLICY_STATE` / `AA_POLICY_SOURCE`. The
posture a session actually ran under is therefore readable at the top of its
output, rather than inferred afterwards from what the tool was or was not stopped
from doing. Add `--dry-run` to see the whole launch — including a policy receipt
naming the state, the source and the reason — without executing anything.

A `claude` started directly inherits neither the proxy nor
`NODE_EXTRA_CA_CERTS` and is **not protected**. This is a measured bypass, not a
theoretical one — AAASM-5276 asserts it positively — and `status` reports it as a
bypass rather than as an Agent Assembly failure. The distinction matters because
the remedy is different.

`aasm run claude --dangerously-skip-permissions` (and `--bare`) prints a warning
and **passes the flag through unchanged**. Agent Assembly's interception sits
below Claude Code's own permission enforcement, so stripping the flag would
change your session without changing what is protected.

## Step 7 — Verify, and the exit `6` that means "not measured"

```console
$ aasm integrations verify claude-code
claude-code — verification passed
  ran at:               1785391172 (unix)
  protected path exercised: yes

Assertions:
  [ok] protected_path_exercised               the core redacted 1 credential finding(s) from the
                                              probe request to api.anthropic.com, and re-inspection
                                              of the bytes it resolved to forward found none
  ...
$ echo $?
0
```

> ### ⚠ Exit `6` means "not measured", not "measured and failed"
>
> `verify` succeeds only when the outcome is `passed` **and** the protected path
> was actually exercised. Exercising it means knowing what the payload leaving
> the machine carries, and **a client on the near side of the proxy cannot see
> that for itself**. So the shipped probe does not guess: it marks its own
> request with an opaque correlation identifier and reads back the proxy's
> verdict for that exact request, including a re-inspection of the payload the
> proxy resolved to forward (`aa-devtool-claude-code/src/adjudicating_probe.rs`).
> The probe's own traffic is terminated at the proxy and never reaches the
> provider.
>
> **You will see exit `6` when the probe cannot measure** — the certificate
> authority is not trusted, nothing on the path adjudicates, the core is
> stopped, the exchange times out, or the deployment is configured `alert_only`
> (observing is not protecting). In every one of those cases the level correctly
> stays at `Integrated`.
>
> A probe that returned `Redacted` because nothing obviously failed would be a
> vacuous pass, and the evidence model exists to prevent exactly that. Read exit
> `6` on an otherwise-clean install as *"not measured"* — and read `status` for
> which condition it is.
The probe uses a **synthetic** secret chosen by the adapter and run by the
service. No real credential is ever read, sent or printed.

## Step 8 — Read status

```console
$ aasm integrations status claude-code
```

`status` reports the achieved level *and the observation that justifies it*,
split by how it was obtained:

* **Exercised evidence** — traffic was produced and adjudicated by the core. The
  only kind that can justify `gateway_protected`.
* **Read-back evidence** — configuration was compared to the receipt. Justifies
  at most `integrated`.
* **Checks that could not be made** — recorded, so the gap is legible rather than
  invisible.

Every rung of the ladder is listed, **including the ones this host cannot
reach**. `host_enforced` renders as *unavailable on this platform* rather than
being omitted: silence there reads as "there is nothing above what I have".

The timestamp is part of the claim. A status says *verified at T*, not *true
now*.

## Step 9 — Repair drift

```console
$ aasm integrations repair claude-code
```

`status` exits `5` when Agent Assembly-owned state no longer matches its receipt.
`repair` re-applies **only** Agent Assembly-owned values; it never rewrites a key
it does not own, even when that key is the cause of the drift — it reports it
instead. `--dry-run` shows what drifted and stops; `--yes` skips the prompt.

Drift is found when `status`/`verify` runs, so a window exists between a change
and its discovery. Some drift is unrepairable in place — the tool removed the
config surface, or its schema changed — and needs a reinstall.

## Step 10 — Remove

```console
$ aasm integrations remove claude-code
```

Removal uses the receipt to restore the pre-install value of every managed key —
restoring the original where one existed, deleting the key where none did — and
removes only Agent Assembly-owned artifacts. `--dry-run` shows the restoration
actions and stops. `--force` answers *"remove anyway and leave those behind"*
for artifacts that could not be reversed; it never removes anything the plan did
not name.

**Restoration is semantics-exact, not byte-exact.** If your settings file used
hand-chosen key ordering or unusual indentation, it will not come back
byte-identical — the write path reserialises the whole document. Every *value*
is restored. See
[Limitations](limitations.md#restore-is-semantics-exact-not-byte-exact).

Without a receipt, removal refuses to guess: it reports what Agent Assembly
believes it owns and requires explicit confirmation before touching anything.

---

## Exit codes

Branch on the code, not on the message.

| Code | Name | Meaning |
|---|---|---|
| `0` | `success` | The operation completed |
| `1` | `internal_error` | A transport or lifecycle failure |
| `3` | `unsupported` | The tool, mechanism or verb is not available here |
| `4` | `incompatible` | This client, the core or the tool version do not agree |
| `5` | `drifted` | Agent Assembly-owned state no longer matches its receipt — run `repair` |
| `6` | `verification_failed` | The protection test did not establish protection |
| `7` | `runtime_unavailable` | No runtime is listening and none could be started |
| `8` | `denied` | The runtime refused this client — re-enrol or fix permissions |
| `9` | `aborted` | Nothing was changed — declined, or no confirmation was possible |

`2` is left to `clap` for usage errors, so "you typed the command wrong" stays
distinguishable from a real outcome.

```bash
aasm integrations verify claude-code || case $? in
  6) echo 'not protected' ;;
  5) aasm integrations repair claude-code --yes ;;
esac
```

---

## Troubleshooting

| Symptom | Exit | What it means | What to do |
|---|---|---|---|
| `the Agent Assembly runtime is not running` | `7` | No socket, and `--no-autostart` was passed. | Start `aa-runtime` with `AA_DEVINT_ENABLED=1`, or drop the flag and let `aasm` start it. |
| A started runtime never binds | `7` | The runtime came up without the DI-API surface. | `AA_DEVINT_ENABLED=1` must be set for it to serve this surface; check the runtime's logs. |
| `<tool> is not installed on this host` | `3` | The adapter is registered; the tool is not. | Install the tool, then re-run. |
| `<tool> <version> is outside the range this adapter supports` | `4` | Version incompatibility. A version below `MIN_VERSION` is reported as *absent* — nothing was written. | Upgrade the tool, or upgrade Agent Assembly. |
| `<reason> — upgrade …` on connect | `4` | This `aasm` and the running core do not share a DI-API version. | Upgrade both; they ship as one versioned unit. |
| A `DEGRADED` negotiation | — | The negotiated DI-API version lacks some verbs; `unavailable_verbs` names them. Never a silent downgrade. | Upgrade the older side. Do not use the missing verbs. |
| `status` reports drift | `5` | Live state no longer matches the receipt. The reported level drops **before** repair is attempted. | `aasm integrations repair <tool>`. If unrepairable, reinstall. |
| `this is NOT a protection measurement` | `6` | The protected path was never exercised and adjudicated — see [Step 7](#step-7--verify-and-the-exit-6-that-means-not-measured). | Launch through `aasm run claude` so traffic is produced, then verify again. A launch with no policy configured ([Step 5](#step-5--write-the-policy-the-session-will-run-under)) is refused and produces none. |
| `the install is partial — N step(s) failed` | — | Some steps applied, some did not. Never a reduced protection level. | `status`, then `repair` or `remove`. |
| `no integration receipt records <tool>` | — | Nothing has been installed to act on. | `aasm integrations install <tool>` first. |
| `the capability token at … is mode 644` | `8` | The token is readable by more than its owner, so it is **refused rather than used** — a filesystem mistake must not become a silent authentication downgrade. | `chmod 600` it and restart the runtime to re-issue. |
| `this aasm is not enrolled with the running runtime` | `8` | No capability token. There is no anonymous tier. | Restart the runtime; enrolment happens on start. |
| Apply refused for `codex` / `github-copilot` / `windsurf-cascade` | `3` | These are carried by `LegacyAdapterShim`; their plan steps name no destination file. | Nothing to do — the refusal is deliberate, and preferable to a success that performed nothing. |

---

## Who is responsible for what

A recurring source of confusion is which component decides anything. It is
always the core.

| Layer | Owns | Never does |
|---|---|---|
| **`aasm integrations` / a plugin / an IDE extension** | Rendering, prompting, choosing a scope and profile, showing evidence. | Mutating tool config, evaluating policy, scanning content, or deriving a protection level. |
| **`DevToolIntegration`** (`aa-devtool-claude-code`) | Per-tool knowledge: detection, which files and keys exist, authoring the plan, declaring bypasses. Runs *inside* the trusted runtime. | Deciding policy outcomes, or asserting protection on the core's behalf. |
| **Core runtime and gateway** | Policy evaluation, sensitive-data detection and redaction, egress allow/deny, approvals, audit, and the protection level itself. | Trusting a client's claim about any of the above. |

**MCP is optional.** It is one of the mechanisms an integration may govern —
specifically, *which* MCP servers the tool may load — and it is not the
integration architecture. The client-to-core protocol is the
[DI-API](developer-integration-api.md), not MCP. An integration that uses no MCP
at all is fully governed; an integration that uses MCP is governed by exactly the
same mechanisms. See the
[thin-client reference implementation](reference-client.md).

---

## Where to go next

* [Protection levels](protection-levels.md) — what `Integrated`,
  `Gateway Protected` and `Host Enforced` mean, and their testable entry criteria.
* [Limitations and known bypasses](limitations.md) — what this does not cover,
  split into what was demonstrated and what was only inferred.
* [`aasm integrations` CLI](cli.md) — the full command reference.
* [L0–L3 Capability Matrix](../governance/capability-matrix.md) — the
  per-capability tier declarations.
