# aasm run

Launch an AI agent — a supported developer tool or a program you own — inside
Agent Assembly's governed launch path: identity registration, policy
resolution, proxy wiring, and (optionally) an execution-isolation boundary,
resolved once and applied consistently whether you preview it or run it.

> **Availability.** `aasm run` is one of three command groups gated behind the
> `devtool` region in `aa-cli/src/commands/mod.rs` (the others are `aasm tools`
> and `aasm integrations`). `.ci/strip-for-publish.sh` removes that region from
> the **crates.io** publish only — `cargo install aasm` does not have `aasm
> run`. A source build (`cargo build -p aa-cli`), the GitHub Release tarballs,
> the `curl` installer, and the Homebrew formula all ship the unstripped tree
> and do have it. See [CLI Reference — Overview](overview.md#command-groups).

## Synopsis

```text
aasm run <TOOL> [TOOL_ARGS...] [OPTIONS]
aasm run exec [OPTIONS] -- <PROGRAM> [ARGS...]
```

Two forms, both entering the same identity/policy/lifecycle/isolation/evidence
flow (ADR 0035 §1):

- **Dev-tool form** — `<TOOL>` is one of the built-in adapters: `claude`,
  `codex`, `copilot`, `windsurf`. The longer ids `aasm integrations list`
  prints (`claude-code`, `github-copilot`, `windsurf-cascade`, …) are accepted
  too and resolve to the same adapter. Everything after `<TOOL>` is forwarded
  verbatim to the launched tool.
- **Generic command form** — `aasm run exec [run-options] -- <program>
  [args...]` launches a program you own. `exec` is resolved only after every
  tool id has failed to match, so it can never shadow a real tool. There is no
  adapter for a generic command: no managed settings are generated or applied,
  and `aasm run` cannot detect whether the program is installed before
  attempting to launch it — the launch attempt itself is the test, and
  `exec`'s own `No such file or directory` is the answer if it is not.

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--agent-id <ID>` | string | _(derived)_ | Override the agent identity for this session. |
| `--team-id <ID>` | string | _(none)_ | Team identifier for this session. |
| `--root-agent <ID>` | string | _(none)_ | Root agent identifier for lineage tracking. |
| `--governance-level <LEVEL>` | enum | _(policy default)_ | Override the governance level for this session. |
| `--no-proxy` | flag | off | Launch **without** routing the tool through the governed proxy — an explicit opt-out of transport mediation. Without it, `aasm run` refuses to launch unless it can establish a trusted local proxy endpoint; it never launches unproxied by accident. Refused outright on a host where another party has already required managed operation of the named tool. |
| `--policy <PATH>` | path | _(resolved from `$AA_POLICY` / default locations)_ | Policy YAML file this session runs under. A launch refuses when no effective policy resolves — an unconfigured policy is never an implicit allow-all. |
| `--workdir <DIR>` | path | _(inherited from this shell)_ | Directory the launched process starts in. Checked before anything is registered or started; a launch that cannot start where it was told to is refused, not silently redirected. |
| `--dry-run` | flag | off | Show the resolved launch — identity, policy, proxy, managed settings, launch command, environment, and the execution-isolation report — without executing anything. |
| `--enforcement-mode <MODE>` | `enforce` \| `observe` \| `disabled` | `enforce` | Enforcement posture for this session, overriding the policy default. `observe` records decisions but never applies them — the tool sees Allow for every action, and shadow events land in the audit log. |
| `--observe` | flag | off | Shorthand for `--enforcement-mode observe`. Mutually exclusive with `--enforcement-mode`. |
| `--isolation <INTENT>` | `none` \| `auto` \| `process` | `none` | How much execution isolation this launch requires. See [Isolation intent](#isolation-intent---isolation) below. |
| `--isolation-backend <ID>` | string | _(unset — `auto` selects by capability, `process` defaults to `sandlock`)_ | Pin the concrete isolation backend by id. Advanced and diagnostic only — see [Backend pinning](#backend-pinning---isolation-backend). |

## Isolation intent (`--isolation`)

`--isolation` states a **backend-neutral isolation class** the launch
requires (ADR 0035 §3) — never a backend or mechanism name. Three values:

| Value | Meaning |
|---|---|
| `none` (default) | No execution-isolation boundary is established. This is the pre-existing behaviour every `aasm run` had before this flag existed, stated explicitly rather than left as an absence — the report can then say *why* a run has no boundary: nobody asked for one, versus one was asked for and could not be built. |
| `auto` | Agent Assembly selects a backend by capability: it walks the compiled-in backends in a fixed order and picks the first one that can meet this launch's lowered policy requirements, using the same negotiation every real launch goes through. It is not "isolate if convenient": when no compiled-in backend can meet the requirements, `auto` refuses — naming every backend it considered and why — rather than running unconfined or silently picking a default. |
| `process` | Confine the launch and its descendants within one host's process model. |

**The default is deliberate, not neutral.** Turning isolation on by default
would sandbox every existing user's tool in a release they did not read the
notes for, and a governed launch that suddenly cannot write to the operator's
own repository is worse than one that states plainly what it is not doing.
Changing the default is a separate product decision, not a side effect of this
flag existing.

**`auto` and `process` both refuse rather than degrade silently.** Neither
ever falls back to `none`. When the selected backend cannot be used on this
host, the launch is refused with the reason and a pointer to `--isolation
none` as the explicit, deliberate way to launch unconfined:

```text
Error: refusing to launch: an execution-isolation boundary was requested and the `sandlock`
backend cannot be selected on this host — <reason>.

There is no fallback. A launch that asked for a boundary and quietly ran without one would
report as governed while being unconfined, which is the failure this mode exists to prevent.
Install the backend, or re-run with `--isolation none` to launch unconfined deliberately.
```

Under `--dry-run` the same condition does not stop the preview — it prints a
`warning:` pair to stderr and reports what a live launch would do, because a
preview exists precisely to answer "what would happen" from a machine that is
not yet fully set up.

See [Security Model → Execution isolation](../security/execution-isolation.md)
for what each isolation class actually achieves — pre-effect denial versus
observation — and the [platform/backend support matrix](../security/execution-isolation.md#platform-and-backend-support-matrix).

## Backend pinning (`--isolation-backend`)

`--isolation-backend <ID>` is **not product vocabulary and not a policy
dimension**. Policy describes required isolation *properties*; naming a
mechanism is a diagnostic escape hatch for reproducing a result on a specific
backend and for telling two backends apart in a bug report. Ordinary
operation should use `--isolation` alone.

- `--isolation-backend` combined with `--isolation none` is refused as a
  contradiction: naming a backend for a launch that asked for no boundary
  would leave the operator believing one half of the request took effect.
- `--isolation-backend` always wins over `auto`'s capability-based selection:
  `--isolation auto --isolation-backend <ID>` names that backend outright and
  reports its own refusal if it cannot meet the launch's requirements — it
  does not fall through to a different backend automatic selection would
  have picked.
- Naming a backend this build does not have is refused, naming the one it
  does have.
- The exact string it accepts is an implementation fact recorded in the
  [platform/backend support matrix](../security/execution-isolation.md#platform-and-backend-support-matrix) — it is not repeated here because this
  page documents the CLI contract, and the matrix is the place that fact is
  allowed to change without this page changing.

## Dry-run output

`aasm run --dry-run <tool-or-exec-invocation> [options]` prints the full
resolved plan and executes nothing — the *same* resolution code path a live
launch uses (`ResolvedRunPlan::bind`), so what you see is what a live run
would do, not a separately-built preview that can drift from it. The output
has one section per stage of the plan:

```text
--- aasm run dry-run ---
agent_id:    ...
agent_did:   ...
trace_id:    ...
session_id:  ...

--- preview fidelity ---
...

--- protection ---
state:  ...
detail: ...

--- policy ---
state:  ...
source: ...
detail: ...

--- execution isolation ---
... (human-readable isolation report — see below)

--- execution isolation (machine-readable) ---
... (key=value lines, for scripting)

--- managed settings ---
...

--- launch command ---
working_dir: ...
...

--- environment ---
...
```

The `--- execution isolation ---` and `--- execution isolation (machine-readable) ---`
sections are printed **unconditionally**, on every launch, including
`--isolation none`. A section that appeared only once a backend was selected
would make "no boundary was established" look like a formatting quirk rather
than a fact about the run — so the report always states, per capability
domain, whether policy left the domain unset, whether the policy schema has
no way to express it at all, or what was actually planned. See
[Execution isolation → Requested vs. achieved](../security/execution-isolation.md#requested-vs-achieved-the-report-shape)
for what the report's fields mean, including the states that read like a
restriction but are not one (`PolicyCannotExpress` is never "no restriction
required").

The machine-readable block is an explicit, versioned contract for scripting: a
`--- execution isolation (machine-readable) ---` header followed by `key=value`
lines, so a consumer can anchor on the header and read records until the first
line that is not one, without parsing prose.

## Examples

Launch Claude Code under governance, with no isolation boundary (unchanged
pre-existing behaviour):

```console
$ aasm run claude
```

Preview a generic command's launch plan without running it:

```console
$ aasm run exec --dry-run -- python agent.py --task "summarize repo"
```

Launch a generic command with the strongest isolation class this build can
provide, refusing rather than running unconfined if it cannot be provided:

```console
$ aasm run exec --isolation auto -- python agent.py
```

Require process-level isolation explicitly, and preview it first:

```console
$ aasm run exec --isolation process --dry-run -- python agent.py
$ aasm run exec --isolation process -- python agent.py
```

For a full governed walkthrough with the isolation report explained line by
line, see [Execution isolation → Quickstart](../security/execution-isolation.md#quickstart-a-governed-isolated-launch).
