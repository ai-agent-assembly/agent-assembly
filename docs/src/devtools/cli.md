# `aasm integrations` — the Developer Integration lifecycle from the CLI

`aasm integrations` is the reference client for the
[Developer Integration API](developer-integration-api.md). It installs,
inspects, verifies, repairs and removes an AI dev tool's Agent Assembly
integration — without you editing the tool's configuration or needing to know
which mechanisms its adapter selected.

It is *only* a client. It holds no per-tool knowledge, performs no mutation of
its own, and never derives a protection state locally. Every per-tool fact
arrives over one socket from an adapter inside the trusted runtime, and every
mutation happens there
([ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md) §1,
forbidden design 10).

## The journey

| Stage | Command | What it does |
|---|---|---|
| Discover | `aasm integrations list` | Detected tools and versions, adapter/core compatibility, integration state, achieved protection level, drift warnings |
| Preview | `aasm integrations plan <tool>` | The material changes an install would make. **Mutates nothing** |
| Install | `aasm integrations install <tool>` | Shows the changes and the permissions required, then applies after confirmation |
| Verify | `aasm integrations verify <tool>` | Runs the protection test and reports what it established |
| Inspect | `aasm integrations status <tool>` | The achieved level and the evidence behind it |
| Repair | `aasm integrations repair <tool>` | Restores AASM-owned state that drifted |
| Remove | `aasm integrations remove <tool>` | Restores what the integration replaced, via the receipt |

## The runtime must be running — and `aasm` will start it

Lifecycle operations run inside `aa-runtime`, which owns the only audited
implementation of them. There is **no in-process `--local` fallback**: that
would be a second code path with a different trust model, which is what
[ADR 0004](../adr/0004-governance-enforcement-flow.md) rejected for transports
and what ADR 0030 §7.1 rules out here.

The consequence is absorbed by the CLI rather than by you. When no runtime is
listening, `aasm` starts one, says so on **stderr**, and waits for it to be
ready:

```console
$ aasm integrations list
Starting Agent Assembly runtime…
Agent Assembly core 0.0.1-rc.6 (DI-API v2)

TOOL             VERSION      COMPAT       STATE          PROTECTION
claude-code      2.1.220      compatible   ladder         detected_not_integrated
codex            0.144.6      compatible   ladder         detected_not_integrated
github-copilot   -            unknown      ladder         not_installed
windsurf-cascade -            unknown      ladder         not_installed
```

Pass `--no-autostart` to turn a missing runtime into exit code `7` instead. Use
it in CI, where leaving a daemon behind is worse than failing.

A missing socket is never silently retried: it means *the runtime is not
running*, which is a bootstrap action, not a transient error.

## Profiles

`--profile` selects what the integration *does about* what it detects. A
profile is what you chose; a **level** is what the system can prove it is
currently doing. See the [product brief](product-brief.md) §6 and §7.

| Profile | Enforcement | Sensitive-data finding | Notes |
|---|---|---|---|
| `recommended` (default) | Enforce | Redact and proceed | The default for every persona unless org policy says otherwise |
| `strict` | Enforce | Redact, and block on configured high-severity classes | Narrower egress allowlist, more approvals |
| `observe-only` | Observe | Recorded; payload forwarded unchanged | **Never displayed as protection.** Status says monitoring |

`--scope` selects the configuration surface (`user`, `project`, `managed`). It
is explicit and is never inferred from your working directory.

## Status is evidence-backed

`status` reports the achieved level *and the observation that justifies it*,
split by how it was obtained:

* **Exercised evidence** — traffic was produced and adjudicated by the core.
  The only kind that can justify `gateway_protected`.
* **Read-back evidence** — configuration was compared to the receipt. Justifies
  at most `integrated`.
* **Checks that could not be made** — recorded so the gap is legible.

Every rung of the ladder is listed, **including the ones this host cannot
reach**. `host_enforced` is rendered as `unavailable on this platform` rather
than omitted: silence there reads as "there is nothing above what I have".

The timestamp is part of the claim. A status says "verified at T", not "true
now".

## Verify is a measurement, not a settings check

`verify` reports success **only** when the service's outcome is `passed` *and*
the protected path was actually exercised. A configuration that reads back
exactly as its receipt records it proves that a file is correct; it proves
nothing about traffic, and this command will not let it read as protection:

```console
$ aasm integrations verify claude-code
claude-code — verification passed
  ran at:               1785391172 (unix)
  protected path exercised: no

Assertions:
  [--] protected_path_exercised               nothing protective was observed on the model-bound path
  ...

This is NOT a protection measurement. Configuration that exists is not evidence
that anything was protected; the protected path must be exercised and adjudicated.
$ echo $?
6
```

The probe uses a **synthetic** secret chosen by the adapter and run by the
service. No real credential is ever read, sent or printed.

## Machine-readable output

`--output json` and `--output yaml` emit the same model the human rendering is
built from, so anything you can read is something a script can parse. The JSON
contains no raw sensitive data: the DI-API's response types have no field able
to hold a rendered settings body, an environment-variable value, a policy
document or a credential, and these reports are built only from those types.

Reports go to **stdout**; notices, prompts and errors go to **stderr**, so
`aasm integrations status claude-code --output json | jq` works even when the
runtime had to be started first.

Mutating commands (`install`, `repair`, `remove`) need `--yes` when there is no
terminal to ask on, or when output is machine-readable. Without it they abort
and change nothing — silence is not consent.

## Exit codes

Branch on the code, not on the message.

| Code | Name | Meaning |
|---|---|---|
| `0` | `success` | The operation completed |
| `1` | `internal_error` | A transport or lifecycle failure |
| `3` | `unsupported` | The tool, mechanism or verb is not available here |
| `4` | `incompatible` | This client, the core or the tool version do not agree |
| `5` | `drifted` | AASM-owned state no longer matches its receipt — run `repair` |
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

## Enrolment

The DI-API has no anonymous tier. The runtime issues a capability token for the
locally installed `aasm` as it starts and writes it `0600` into
`~/.aa/run/devint.token`, beside the `0700` socket directory. A token in a file
that is readable by more than its owner is **refused rather than used** — a
filesystem mistake must not become a silent authentication downgrade.

If you see `this aasm is not enrolled with the running runtime`, restart the
runtime; enrolment happens on start.

## Errors you may meet

| Message | What it means | What to do |
|---|---|---|
| `<tool> is not installed on this host` | The adapter is registered, the tool is not | Install the tool, then re-run |
| `<tool> <version> is outside the range this adapter supports` | Version incompatibility | Upgrade the tool, or upgrade Agent Assembly |
| `the Agent Assembly runtime is not running` | No socket, and `--no-autostart` was passed | Start `aa-runtime` with `AA_DEVINT_ENABLED=1`, or drop the flag |
| `<reason> — upgrade …` on connect | This `aasm` and the running core do not share a DI-API version | Upgrade both; they ship as one versioned unit |
| `the install is partial — N step(s) failed` | Some steps applied, some did not | `aasm integrations status <tool>`, then `repair` or `remove` |
| `this is NOT a protection measurement` | The protected path was not exercised | Launch the tool through the managed path, then verify again |
| `the capability token at … is mode 644` | The token is not a secret any more | `chmod 600` it and restart the runtime to re-issue |
| `no integration receipt records <tool>` | Nothing has been installed to act on | Run `aasm integrations install <tool>` first |

## Claude Code

Claude Code is the first natively migrated integration
([AAASM-5281](https://lightning-dust-mite.atlassian.net/browse/AAASM-5281)).
`aasm integrations install claude-code` applies five steps and offers a sixth:

| Step | What it does |
|---|---|
| `managed-settings` | Merges four Agent Assembly-owned keys into the settings file for the scope you chose. Every other key is left exactly as it was. |
| `proxy-ca` | Copies the proxy's certificate authority to a PEM Agent Assembly owns. The system trust store is **not** touched. |
| `node-extra-ca-certs` | Sets `NODE_EXTRA_CA_CERTS` for every governed launch. **Without this the interception handshake fails and nothing is inspected.** |
| `proxy-env` | Routes governed launches through the local proxy. |
| `side-channel-scope` | Asks the proxy to inspect `api.anthropic.com` and `*.anthropic.com` for this integration — Claude Code's telemetry and registry calls, not just `/v1/messages`. `llm_only` stays on, so nothing else on your machine is intercepted. |
| `protection-test` | Optional. Sends a synthetic secret down the model path so the core can adjudicate what the provider received. |

### Choose the scope; it is never inferred

`--scope user` writes `$CLAUDE_CONFIG_DIR/settings.json` (or
`~/.claude/settings.json`); `--scope project` writes
`<cwd>/.claude/settings.json`. A `.claude/` directory in your working directory
never redirects a user-scoped install — which file is written is a decision you
make and the receipt records. `--scope managed` is refused: the endpoint
managed-settings file is administrator-owned, its enforcement keys are
unmeasured, and installing them would need a privileged step this integration
does not take.

### Protection applies to the managed launch

Start Claude Code with `aasm run claude`. A `claude` started directly inherits
neither the proxy nor `NODE_EXTRA_CA_CERTS` and is **not** protected — this is a
measured bypass, not a theoretical one, and `status` says so rather than
implying otherwise.

### What is deliberately not offered

* **`ANTHROPIC_BASE_URL` redirection.** Measured in AAASM-5276 delivering a
  synthetic secret to the provider with no Agent Assembly component anywhere in
  the path. It is routing, not protection, and setting it in the shell also
  suppresses Claude Code's server-managed settings fetch.
* **Hooks, for sensitive data.** They govern tool and action execution and
  cannot see model-bound content, so no hook can carry a protection claim.
* **`NODE_TLS_REJECT_UNAUTHORIZED`.** Never set. A TLS failure is a finding, not
  something to suppress — and if you have it set, `status` reports it as a
  bypass.
* **The system keychain and the endpoint managed-settings file.** Both are
  privileged host changes whose behaviour is unmeasured.

### Bypasses that are detected

`bypassPermissions` in a settings file, `ANTHROPIC_BASE_URL` /
`CLAUDE_CODE_API_BASE_URL` in the shell or in a settings `env` block,
`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX`, and `NODE_TLS_REJECT_UNAUTHORIZED`.
`aasm run claude --dangerously-skip-permissions` (and `--bare`) prints a warning
and passes the flag through unchanged — Agent Assembly's interception sits below
Claude Code's own permission enforcement, so stripping the flag would change
your session without changing what is protected.

Bypasses that **cannot** be observed are stated in every plan rather than left
to be inferred from silence: launching outside `aasm run`, repointing
`CLAUDE_CONFIG_DIR`, symlinking `.claude`, editing the settings file directly,
replacing the binary, or calling the API from another program with your own key.

## Current limitation

Adapters other than Claude Code have not yet migrated to the Developer
Integration lifecycle and are carried by `LegacyAdapterShim` (ADR 0030 §7). They
can be **discovered, planned and reported on**, but their plan step names no
destination file, so the service refuses to apply it rather than reporting a
success nothing performed.

`verify` needs a probe that can adjudicate what the provider received. A default
build has none — a client on the near side of the proxy cannot see the forwarded
body — so `verify` reports the model path as configured but never exercised, the
level stays at `Integrated`, and the command **exits `6`**. That is the honest
reading: configuration alone is not evidence that anything inspected the traffic.
See [Limitations](limitations.md#what-verify-adjudicates-and-when-it-still-exits-6).

## See also

* [Onboarding a Developer Integration](onboarding.md) — the same journey as a
  walkthrough, with troubleshooting.
* [Protection levels](protection-levels.md) — what `Integrated`,
  `Gateway Protected` and `Host Enforced` mean.
* [Limitations and known bypasses](limitations.md).
