# `aasm integrations`

Install, verify, repair and remove **Developer Integrations** for AI dev tools —
the governance wiring that makes a tool like Claude Code run through Agent
Assembly instead of straight out to its provider.

> **Absent from `cargo install aasm` — and only from there.** `aasm integrations`
> is a developer-only command group. Like
> [`aasm run` and `aasm tools`](overview.md#command-groups), it is gated behind
> the `devtool` region in `aa-cli/src/commands/mod.rs` and `aa-cli/Cargo.toml`,
> and `.ci/strip-for-publish.sh` removes that region in the **`publish-crates`**
> job of `release.yml` — the crates.io publish and nothing else. A source build
> (`cargo build -p aa-cli`), the GitHub Release tarballs, the `curl` installer
> and the Homebrew formula are all built from the unstripped tree, so **they do
> carry this command**. Where the strip does apply it is not cosmetic: a
> crates.io `aa-runtime` never binds the DI-API socket this command talks to, so
> the surface would have nothing to connect to.

This page is the **command reference** — subcommands, flags, defaults, exit
codes. For what the lifecycle *means* (profiles, evidence, protection levels,
what is and is not measured), read
[`aasm integrations` in the Developer Integrations section](../devtools/cli.md)
and [Protection levels](../devtools/protection-levels.md).

## What it is, in one paragraph

`aasm integrations` is a **client** of the
[Developer Integration API](../devtools/developer-integration-api.md) and
nothing more. It holds no per-tool knowledge, performs no mutation of its own,
and never derives a protection state locally: every per-tool fact arrives over
one Unix socket from an adapter inside the trusted `aa-runtime`, and every
mutation happens there. That is why the command needs a **running runtime** —
there is no in-process fallback, by design
([ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md)
§7.1).

## Invocation

```text
aasm integrations [OPTIONS] <COMMAND> [ARGS]
```

| Subcommand | Argument | Mutates | Purpose |
|---|---|---|---|
| `list` | — | no | Detected tools, compatibility, integration state, protection |
| `plan <TOOL>` | tool id | **no** | Exactly what an install would change |
| `install <TOOL>` | tool id | yes | Apply, after showing the changes and the permissions |
| `status <TOOL>` | tool id | no | The protection level and the evidence behind it |
| `verify <TOOL>` | tool id | no | Run the protection test and report what it established |
| `repair <TOOL>` | tool id | yes | Restore AASM-owned state that drifted |
| `remove <TOOL>` | tool id | yes | Undo the integration, restoring what it replaced |

`<TOOL>` is the tool id as `aasm integrations list` reports it —
`claude-code`, `codex`, `github-copilot`, `windsurf-cascade`.

These same ids are accepted by [`aasm run`](overview.md#command-groups), which
has its own shorter canonical spellings (`claude`, `codex`, `copilot`,
`windsurf`). An id copied out of `aasm integrations list` launches the tool it
names; the two commands do not have separate vocabularies.

> **Only `claude-code` has a lifecycle today.** The other three are carried by
> `LegacyAdapterShim`: they detect and report, but `install` and `repair` are
> **refused with exit `3`** because their plan steps name no destination file.
> That refusal is deliberate — a success that performed nothing would be worse.
> Being listed means the tool is recognised, not that it can be integrated; see
> [Limitations](../devtools/limitations.md).

## Options common to every subcommand

The [global options](overview.md#global-options) (`--context`, `--output`,
`--api-url`, `--api-key`) apply, plus one flag defined on the group itself:

| Flag | Default | Description |
|---|---|---|
| `--no-autostart` | off | Report a stopped runtime (exit `7`) instead of starting one. |
| `--allow-unverified-runtime` | off | Proceed against a runtime whose build cannot be shown to be this one. See [`10` and `11`](#10-and-11--which-build-answered). |

### `--no-autostart`

Lifecycle commands need a running Agent Assembly runtime. By default `aasm`
**starts one**, says so on stderr, and waits:

```console
$ aasm integrations list
Starting Agent Assembly runtime…
```

A missing socket is a bootstrap action, not a transient error — it is never
silently retried. Pass `--no-autostart` in CI, where leaving a daemon behind is
worse than failing; the missing runtime then becomes exit code `7`
(`runtime_unavailable`) instead.

### `--output json`

`--output json` (and `--output yaml`) emit the **same model** the human table is
rendered from, so anything readable is parseable. Reports go to **stdout**;
notices, prompts and errors go to **stderr**, so
`aasm integrations status claude-code --output json | jq` stays valid even when
the runtime had to be started first.

Machine-readable output also makes the mutating commands non-interactive: there
is nothing on the other end that can answer a prompt, so `install`, `repair` and
`remove` **abort** (exit `9`) rather than block, unless `--yes` is passed.

## `aasm integrations list`

```text
aasm integrations list [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--capabilities` | off | Show every declared mechanism per tool, not just the summary row. |

## `aasm integrations plan <TOOL>`

Mutates nothing. Prints the material changes an install would make, the
permissions it would need, and the mechanisms the tool cannot use with the
reason.

| Flag | Values | Default | Description |
|---|---|---|---|
| `--profile` | `recommended` \| `strict` \| `observe-only` | `recommended` | Which protection profile to plan for. |
| `--scope` | `user` \| `project` \| `managed` | `user` | Which configuration surface to write. Explicit, never inferred from the working directory. |
| `--policy-profile <NAME>` | string | `""` (service default) | The policy profile to resolve, **by name**. The document itself never crosses this boundary. |
| `--allow-privileged-host-steps` | flag | off | Include steps that change host state (trust stores, launch agents). |
| `--install-managed-settings` | flag | off | Install the tool's administrator-managed settings file. Implies `--scope managed` and the privileged-step consent. The file's *installation* is verified by read-back; its *enforcement* is [unmeasured](../devtools/limitations.md#the-managed-settings-file-can-be-installed-its-enforcement-is-still-unmeasured). |

The `--profile` tokens are what you type; the wire tokens the DI-API receives
are `recommended`, `strict` and `observe_only`. `observe-only` computes and
audits every decision and applies none of them, and is **never** displayed as
protection — `status` says monitoring.

### Why `--scope managed` alone is refused

`--scope managed` reads like a third choice next to `user` and `project`, and it
says nothing about administrator authorization. On its own it is therefore
rejected with exit `9` (`aborted`) and a remediation naming the flag that does
mean consent:

```console
$ aasm integrations plan claude-code --scope managed
error: nothing was changed: writing the administrator-managed settings surface needs an explicit opt-in
```

`--install-managed-settings` is that opt-in. It selects the managed surface,
carries the privileged-step consent, and asks for administrator authorization
for **one** file write — the settings surface the tool *documents* as
non-overridable. It is the only route to `Host Enforced`, it is off by default,
and the default install stays fully unprivileged.

Before you are asked to approve anything, the plan states the exact path, the
exact content and its SHA-256, the diff against what is on the host, any
conflict, and the backup and rollback behaviour. An unavailable or denied
authorization is a truthful failure, never a quieter install; a non-interactive
run fails immediately rather than waiting for credentials.

> `Host Enforced` means *the policy is installed where you cannot rewrite it*.
> It does **not** mean a bypass was demonstrated to fail — see
> [Limitations](../devtools/limitations.md). The procedure that would close that
> gap is
> [Measuring managed-settings enforcement](../devtools/managed-device-measurement.md).

## `aasm integrations install <TOOL>`

Takes every `plan` flag above, plus:

| Flag | Default | Description |
|---|---|---|
| `--yes` | off | Apply without asking. Required for non-interactive and machine-readable runs. |
| `--dry-run` | off | Show the plan and stop, exactly as `plan` does. |

The preview you approve is the same plan object that gets applied — not a second
rendering of it — so you cannot consent to something you were not shown.
Silence is not consent: without a terminal and without `--yes`, the command
aborts and changes nothing.

## `aasm integrations status <TOOL>`

No flags beyond the common ones. Reports the achieved protection level *and the
observation that justifies it*, split by how the observation was obtained
(exercised vs read-back vs could-not-be-checked), including the rungs this host
cannot reach. The timestamp is part of the claim: a status says "verified at
T", not "true now".

`Gateway Protected` is reported only on **adjudicated exercised** evidence.
Configuration that reads back correctly justifies at most `Integrated`.

## `aasm integrations verify <TOOL>`

No flags beyond the common ones. Runs the adjudicated protection exercise and
exits `0` only when the protected path was actually exercised *and* the outcome
was protective. Otherwise it exits `6` — read that as **"not measured"**, never
as "measured and failed". The probe uses a synthetic secret chosen by the
adapter and run by the service; no real credential is read, sent or printed.

## `aasm integrations repair <TOOL>`

| Flag | Default | Description |
|---|---|---|
| `--dry-run` | off | Show what drifted and stop. |
| `--yes` | off | Repair without asking. Required for non-interactive and machine-readable runs. |

## `aasm integrations remove <TOOL>`

| Flag | Default | Description |
|---|---|---|
| `--dry-run` | off | Show the restoration actions and stop. |
| `--yes` | off | Remove without asking. Required for non-interactive and machine-readable runs. |
| `--force` | off | Proceed even when the reversal is known to be incomplete. |

Removal is derived from the **receipt**, not re-derived from current host state:
it undoes what was done, not what would be done now. Anything that cannot be
undone automatically is printed as a residual action *first, every time*;
`--force` only answers "yes, remove anyway and leave those behind" and never
removes anything the plan did not name.

Restoration is **semantics-exact, not byte-exact** — the keys Agent Assembly
owns are removed and the prior values restored, but formatting and key order in
a file someone else also writes are not guaranteed to be reproduced verbatim.

## Exit codes

`aasm integrations` gives every outcome its own code so a wrapper can branch on
the code rather than parse English out of stderr. The table below is generated
from `aa-cli/src/commands/integrations/exit.rs` and printed by
`aasm integrations --help`.

| Code | Name | Meaning |
|---|---|---|
| `0` | `success` | The operation completed. |
| `1` | `internal_error` | A transport or lifecycle failure. |
| `3` | `unsupported` | The tool, mechanism or verb is not available here. |
| `4` | `incompatible` | This client, the core or the tool version do not agree. |
| `5` | `drifted` | AASM-owned state no longer matches its receipt — run `repair`. |
| `6` | `verification_failed` | The protection test did not establish protection. |
| `7` | `runtime_unavailable` | No runtime is listening and none could be started. |
| `8` | `denied` | The runtime refused this client — re-enrol or fix permissions. |
| `9` | `aborted` | Nothing was changed — declined, or no confirmation was possible. |
| `10` | `runtime_unverified` | The runtime that answered was shown **not** to be this build — stop it and re-run. |
| `11` | `runtime_unverifiable` | The runtime that answered carries no build identity, so nothing was established either way. |

**`2` is deliberately unused.** `clap` exits `2` for a usage error, so reusing it
would make "you typed the command wrong" indistinguishable from a real outcome.

```bash
aasm integrations verify claude-code || case $? in
  6) echo 'protection not measured — treat as unprotected, do not report a failed block' ;;
  5) aasm integrations repair claude-code --yes ;;
esac
```

### `10` and `11` — which build answered

These two are about the runtime that served the command, not about the tool it
was asked about. A reachable socket is not evidence that the *right* thing
answered: a runtime built from another checkout, or one whose executable has been
deleted, answers perfectly well and describes **its** host. That is how a healthy
Claude Code once got reported as `not_installed`.

Every `aasm integrations` command therefore checks which build answered, before
producing any output.

| Code | Standing | When |
| --- | --- | --- |
| `10` `runtime_unverified` | **refuted** | The runtime was *shown* not to be usable as this build: a different `build_sha` or `core_version`, an `executable_path` that no longer exists, or more than one runtime listening at once. A positive finding. |
| `11` `runtime_unverifiable` | **unverifiable** | The runtime's identity could be neither confirmed nor refuted: one or both sides carry no authoritative build identity, or the peer predates DI-API v4 and cannot state one. An absence, not a finding. |

**Which commands emit which:**

| Command | Reads or writes | Exit `10` | Exit `11` |
| --- | --- | --- | --- |
| `aasm integrations list` | read-only | yes | **no** — answers, and reports `unverifiable` |
| `aasm integrations plan` | read-only | yes | **no** — answers, and reports `unverifiable` |
| `aasm integrations status` | read-only | yes | **no** — answers, and reports `unverifiable` |
| `aasm integrations install` | writes host state | yes | **yes** |
| `aasm integrations verify` | asserts enforcement is established | yes | **yes** |
| `aasm integrations repair` | writes host state | yes | **yes** |
| `aasm integrations remove` | writes host state | yes | **yes** |

Read-only commands still answer under an unverifiable standing because refusing
them would make the situation undiagnosable — they are exactly the commands you
use to find out *which* runtime answered and stop the wrong one. They say so on
stderr, and `--output json` carries the standing so a recorded result stays
marked:

```jsonc
"runtime": {
  "provenance": {
    "standing": "unverifiable",   // verified | unverifiable | refuted
    "verdict": "unverifiable",    // the specific fact behind the standing
    "build_sha": "unknown",
    "build_id_source": "absent",  // injected | checkout | packaged | absent
    "pid": 24601,
    "fields": [                   // which facts were absent, matched, mismatched
      { "field": "build_sha", "status": "absent", "expected": "unknown", "reported": "unknown" }
    ],
    "reachable_runtimes": 1
  }
}
```

**`unverifiable` is never reported as verified**, on any surface or in JSON.
Branch on `standing`, not on the presence of a `build_sha`.

**`reachable_runtimes` is one-directional evidence.** Above one it *proves*
ambiguity — each of those sockets was connected to, so each of those runtimes
exists, and the result cannot be attributed to one of them. Equal to one it
proves only that nothing else was **found**: the scan probes files named
`devint*.sock`, in the answering socket's own directory, once as the session
opens. A runtime under another name, in another directory (which
`AA_DEVINT_SOCKET` makes trivial), or started a moment later is not counted.
Read `1` as "no duplicate was observed", never as "this is the only runtime".

`standing` is the one field that folds in *every* reason a result may not be
attributable, which is why it is the only one a wrapper needs to read.
`verdict` is narrower — it reports the **identity comparison** alone, and two
runtimes compiled from one commit have identical identities, so `verdict` reads
`verified` for both of them. `standing` cannot read `verified` while
`reachable_runtimes` is above one.

A wrapper that records evidence should refuse anything but `verified`:

```bash
aasm integrations status claude-code --output json > result.json || case $? in
  10) echo 'the wrong runtime answered — stop it and re-run'; exit 1 ;;
  11) echo 'the runtime carries no build identity'; exit 1 ;;
esac
jq -e '.runtime.provenance.standing == "verified"' result.json \
  || { echo 'result is not attributable to this build'; exit 1; }
```

`--allow-unverified-runtime` downgrades both refusals to a stderr warning for a
deliberately mixed installation. It does **not** change what is reported: the
standing reaches `--output json` *and* rides above the result in the table
rendering, so a result obtained through it stays marked as unverified rather
than passing as verified.

It also disarms the **multiplicity** refusal, which is not an identity cause at
all. With more than one runtime reachable the command answers from whichever one
it connected to and the others are never consulted; `reachable_runtimes` says how
many there were, and `standing` cannot read `verified` while that is above one.

## Environment

| Variable | Read by | Effect |
|---|---|---|
| `AA_DEVINT_ENABLED` | `aa-runtime` | Must be truthy for the runtime to serve the DI-API at all. **Off by default.** |
| `AA_DEVINT_SOCKET` | runtime + clients | Overrides the DI-API socket path (`~/.aa/run/devint.sock`). |
| `AA_DEVINT_TOKEN_FILE` | runtime + clients | Overrides the capability-token (enrolment) file path. |
| `AASM_STATE_DIR` | `aa-core`, `aa-proxy` | Root of the integration receipt store (`${AASM_STATE_DIR:-~/.aasm}/integrations/`). |

See [Configuration → Environment variables](../quick-start/configuration.md#environment-variables)
for the full table and the file modes these paths are held to.

## See also

- [`aasm integrations` — the lifecycle explained](../devtools/cli.md)
- [Onboarding a Developer Integration](../devtools/onboarding.md) — the same
  journey as a walkthrough, with troubleshooting.
- [Protection levels](../devtools/protection-levels.md)
- [Limitations and known bypasses](../devtools/limitations.md)
- [Developer Integration API](../devtools/developer-integration-api.md)
