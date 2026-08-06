# AAASM-5527 — current-state capability coverage matrix and threat model

The evidence-backed inventory of what Agent Assembly covers today: by which
component, at what time relative to the action, under which platform, launch and
transport assumptions, and with which residual bypasses.

- **Ticket:** [AAASM-5527](https://lightning-dust-mite.atlassian.net/browse/AAASM-5527)
  (Spike, 8 points) · **Epic:** [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526)
- **Goal:** CBLPCRLM-13 — Verified Product Truth and Protection Boundaries
- **Fix version:** agent-assembly v0.0.1-rc.7
- **Compiled:** 2026-08-06, against `remote/main` at `299de3883`
- **Machine-readable source:** [`AAASM-5527-capability-coverage-matrix.yaml`](AAASM-5527-capability-coverage-matrix.yaml)

This artifact **blocks** [AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609)
("What Ships Today" / "Choose Your Enforcement Path") and
[AAASM-5588](https://lightning-dust-mite.atlassian.net/browse/AAASM-5588) (public
Trust and Evidence experience), and **feeds**
[AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) (the
machine-readable capability/evidence manifest). What is recorded here is what
those surfaces are permitted to say. A row that is wrong here becomes a published
claim.

## Why this file lives here

This is an evidence artifact, not book content. It sits in `verification-reports/`
next to [`AAASM-5528-public-claim-inventory.md`](AAASM-5528-public-claim-inventory.md)
and [`AAASM-5276-claude-code-mechanism-matrix.md`](AAASM-5276-claude-code-mechanism-matrix.md)
— the precedent this repository already uses for measured evidence cited from book
pages (`docs/src/devtools/limitations.md` cites the 5276 matrix; ADR 0030 cites it
too). It is deliberately **not** under `docs/src/`: a page there is unreachable
unless registered in `docs/src/SUMMARY.md`, and both `docs/src/**` and `SUMMARY.md`
are held by [AAASM-5592](https://lightning-dust-mite.atlassian.net/browse/AAASM-5592)
concurrently, so a page added there now would render as an orphan. `crates/**` —
in this repository the flat `aa-*` directories at the repo root — is held by
[AAASM-5535](https://lightning-dust-mite.atlassian.net/browse/AAASM-5535).

Consequently every defect this survey found in code or in book pages is **reported
in the [Cross-cutting findings](#cross-cutting-findings-reported-not-fixed) section
rather than fixed here**.

## Relationship to the work this builds on

This spike does not re-derive what Wave 0 already established. It **cites and
re-verifies** those findings and extends them to the paths they did not cover
(MCP transports, host actions, degraded modes, identity propagation, launch
paths).

| Source | What it fixes | How this artifact uses it |
|---|---|---|
| [ADR 0033](../docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md) — Accepted | The canonical architecture: six elements E1–E6; the gateway is a control plane, not a fourth interception layer; eBPF is one Linux mechanism under E4. §6 fixes the claim vocabulary; §5.3 the platform matrix | **Normative.** Every `Coverage` value in this matrix is one of §6's terms, and no row may exceed the ADR's platform matrix |
| [ADR 0030](../docs/src/adr/0030-developer-integration-boundaries-and-trust-model.md) | The protection-state ladder and the evidence rules (`L0Discover < L1Observe < L2Enforce < L3Native` ceilings; `DetectedNotIntegrated → … → GatewayProtected → HostEnforced`) | Supplies the `Current support level` and `Proposed target level` columns for dev-tool rows |
| [`AAASM-5528-public-claim-inventory.md`](AAASM-5528-public-claim-inventory.md) | 69 public claims across three repos, with evidence blocks E1–E7 | Supplies the evidence base; this artifact re-verified E1, E2, E4 and E5 against the current tree rather than trusting the citations |
| [`AAASM-5276-claude-code-mechanism-matrix.md`](AAASM-5276-claude-code-mechanism-matrix.md) and [`docs/src/devtools/limitations.md`](../docs/src/devtools/limitations.md) | The measured Claude Code bypass set, already split into demonstrated and inferred | The [bypass catalogue](#bypass-catalogue) adopts that split and generalises it product-wide |

## Method

### The four questions asked of every row

Each question is invisible to the one before it, which is why all four are asked.
Questions 3 and 4 are the ones that changed answers.

1. **Is the claim worded correctly** — does it name a boundary rather than assert
   an unqualified absolute?
2. **Does the guarantee hold** — what must be true in the code for it to hold, and
   is that true?
3. **Is it on by default**, and if not, what fires instead? A capability that
   exists but is off ships as its default, not as itself.
4. **Does the named mechanism exist at all, and can a released binary reach it?**
   A mechanism present in the source tree but absent from the release artifact set
   is not a shipped capability.

Rows where question 3 or 4 changed the answer are marked **`⚠ Q3`** / **`⚠ Q4`**
in the matrix and collected in [Where questions 3 and 4 changed the
answer](#where-questions-3-and-4-changed-the-answer).

### Probe discipline

Four confident empty results in this programme came from broken probes — a
`crates/` path that does not exist (crates are flat at the repo root), a
`head`-truncated pipe, an unscoped traversal, and a `gh pr diff` that silently
truncated. Accordingly:

- **Every recorded absence was probed with a known-present positive-control term
  in the same command.** Where the matrix says a mechanism is absent, the command
  that established it also matched something that is present, so an empty result
  cannot be a broken probe.
- **Path citations were checked for tracked-ness with `git ls-files
  --error-unmatch`, not for file existence.** A citation into a gitignored,
  build-generated path resolves only for a reviewer whose builds created it. This
  is not hypothetical: ADR 0033 §F records exactly that defect against
  `aa-proto/_embedded/proto/audit.proto`.
- **Line numbers are given alongside the symbol name.** Line numbers rot; a reader
  whose line does not land should search the symbol before concluding the row is
  wrong.

### What "reviewed against source code" means here

Acceptance criterion 6 requires the matrix be reviewed against source, not README
text. Where a code comment and the code it describes disagreed, the code won —
and the disagreement is recorded as a finding, because a comment that contradicts
its own code is a defect in its own right, not merely a stale note.

## Claim vocabulary

This artifact does **not** define its own vocabulary. The `Coverage` column takes
exactly one value from [ADR 0033
§6](../docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md#6-claim-vocabulary--decision-timing-and-failure-posture-are-part-of-every-claim):

> **Observed** · **Detected** · **Evaluated** · **Denied before execution** ·
> **Redacted** · **Approval required** · **Degraded** · **Unmeasured** ·
> **Experimental** · **Planned** · **Unsupported**

Two of those terms are load-bearing here and are routinely conflated elsewhere:

- **Denied before execution** requires that the *decision preceded the effect*. A
  mechanism that terminates a process after the offending syscall has run is
  **Detected**, not denied — the eBPF syscall guard is the case in point.
- **Unmeasured** is scoped to the *action or payload*. A connection may be
  Observed while the payload it carries is Unmeasured; the transparent-tunnel path
  is exactly that. "Unmeasured" never means "nothing happened".

The `Current support level` and `Proposed target level` columns use ADR 0030's
protection ladder for dev-tool rows, and the ADR 0033 §6 vocabulary elsewhere.
The two vocabularies are orthogonal and neither redefines the other (ADR 0033,
Migration checklist §E, "Vocabulary ruling").

## Boundary taxonomy

The ticket requires that the word **`universal`** never appear without one of the
following boundaries. This artifact honours that by never using the word bare;
each row's `Boundary class` column names exactly one of these.

| ID | Boundary class | What it means | What defeats it |
|---|---|---|---|
| **B1** | Universal within one patched function | The guarantee holds for calls that pass through a specific wrapped function and for no others | Calling the underlying function directly; a code path the wrapper does not sit on |
| **B2** | Universal within one framework | Holds for every tool invoked through one framework's tool-dispatch seam, given the adapter is installed and initialised | Using a framework with no adapter; bypassing the framework's own dispatch |
| **B3** | Universal within one process | Holds for everything the process does, regardless of which library performs it | Spawning a child process; another process on the host |
| **B4** | Universal within one container | Holds for every process in a container | A sibling container; the host outside it |
| **B5** | Universal within one host | Holds for every process on the machine | Another machine; a remote/SaaS execution environment |
| **B6** | Universal within one managed device | Holds because a device-management authority the user cannot override installs and pins the control | An unmanaged device; a user with local administrator rights, where the control is not root-owned |
| **B7** | Universal across opaque SaaS agents | Holds for agents whose execution the operator does not control and cannot instrument | Nothing today reaches this class — see the [Go/No-Go section](#go--conditional-go--no-go-per-boundary-class) |

**No mechanism in the shipped product reaches B3, B4, B5 or B7 for the general
case.** The strongest classes actually attained today are B1, B2, and — for
outbound HTTPS from processes launched onto the managed path — a *conditional* B3
that holds only while the process honours the injected proxy environment. That is
the single most important sentence in this artifact and the [minimum defensible
public guarantee](#minimum-defensible-public-guarantee-today) is built from it.

---

# Threat model

## Scope

This threat model covers the **shipped `agent-assembly` release artifact set at
v0.0.1-rc.7** and the three language SDKs that pin it, deployed by an operator who
runs the gateway, and optionally the runtime and the proxy, on a developer
workstation or a single server they control.

It answers one question: *for an action an agent takes, what does Agent Assembly
know about it, when does it know, and can it stop it?*

In scope:

- The six architectural elements E1–E6 of ADR 0033.
- Every execution path enumerated in the [coverage matrix](#the-coverage-matrix):
  framework tool calls, direct calls, shell/subprocess/filesystem/browser/database
  actions, network egress across all transports, MCP across all its transports,
  managed and unmanaged dev-tool launch, and identity propagation.
- Failure and degraded modes of each of those, because a control's behaviour when
  its dependency is unavailable is part of its security property, not an
  operational footnote.

## Explicit non-goals

These are non-goals **by decision**, not by omission. Each is stated so that no
downstream page can imply the opposite by silence.

| # | Non-goal | Why, and where it is already recorded |
|---|---|---|
| **N1** | **Resisting the developer's own UID on their own machine.** A user who can edit their own environment, replace a binary on their `$PATH`, or unset `HTTPS_PROXY` can remove the product from the path | ADR 0033 threat-model table: *"The developer's own UID is not an adversary here"*; ADR 0030 states host-level tamper prevention against the user's own account as an explicit non-goal. The one partial exception is the macOS root-owned managed-settings file, which a non-admin user cannot rewrite — that is B6, not B5 |
| **N2** | **Resisting a fully privileged host administrator** | Epic AAASM-5526 non-goals: *"Claiming resistance against a fully privileged host administrator without a separately enforced trust boundary"* |
| **N3** | **Preventing what is only observed.** Observation is not prevention, and this model never credits a telemetry-only mechanism with a prevention property | Epic AAASM-5526 non-goals: *"Treating observation as prevention"*. ADR 0033 forbidden design 4 |
| **N4** | **Treating installation as runtime evidence.** A settings file on disk, a binary on `$PATH`, an `AA_LAYERS` value or a capability bitflag is not evidence that anything is governed | Epic AAASM-5526 non-goals; ADR 0033 §7 and forbidden design 6; ADR 0030 §4.2 rule 1 |
| **N5** | **Treating one SDK hook as universal** across languages, transports or host actions | Epic AAASM-5526 non-goals. This is why the boundary taxonomy above exists |
| **N6** | **Shipping OS-level enforcement on macOS or Windows.** macOS Endpoint Security and Network Extension are explicit product non-goals; no Windows mediation exists | ADR 0033 §5.3, pinned by a test asserting the literal limitation string (`aa-cli/src/commands/integrations/model.rs:1200,1204`) |
| **N7** | **Governing opaque SaaS agents' execution.** For an agent whose runtime the operator does not control, the product's reach is what the SaaS surface exposes, and the adapter is hard-capped accordingly | `aa-devtool-saas` ceiling; boundary class B7 |
| **N8** | **Confidentiality of the audit chain against someone who can rewrite the log.** The chain is unkeyed; it is tamper-*evident* to a reader who holds an out-of-band copy of a prior head, not a signature | Evidence E5; re-verified below |
| **N9** | **Network-layer transparent capture.** There is no iptables / pfctl / TPROXY / `SO_ORIGINAL_DST` redirect. Traffic reaches the mediator only if the client speaks the HTTP proxy protocol to it | Re-verified below |

## Threat actors and capability assumptions

Four actors, ordered by the capability they are assumed to hold. The model's
obligation differs for each, and conflating them is what produces overstated
claims.

| Actor | Assumed capabilities | What the product must still deliver | Where it holds today |
|---|---|---|---|
| **A1 · The steered agent** — a cooperating, SDK-adopting, managed-launched agent whose *model* has been prompt-injected | Controls tool-call arguments and payload content. Does **not** modify its own binary, environment or launch | Every action on the managed path is Evaluated; a policy `Deny` on a wrapped tool call refuses before the body runs; credentials in inspected outbound requests are Redacted; the reported protection state never exceeds the evidence | **Largely holds.** This is the actor the product is strongest against, and the only one for whom "governed" is close to complete. Residual: raw HTTP, subprocess, and filesystem access from inside the same process are not on any SDK seam |
| **A2 · The careless integrator** — not malicious | Ships secrets in tool arguments or prompts; grants an over-broad capability set; launches a tool outside the managed path by habit | Detect and redact recognised credentials on inspected paths; report the unmanaged launch as *unmeasured*, never as clean | **Partially holds.** Redaction is bounded to the scanner's pattern set and to MitM'd hosts; an unmanaged launch is reported as a bypass for Claude Code, and is invisible for tools with no lifecycle |
| **A3 · The bypassing agent** — deliberately avoids the fastest interception point | Never links the SDK, or links it and does not honour the answer; unsets `HTTPS_PROXY`; uses a TLS stack the uprobes do not hook (Go `crypto/tls`, statically linked BoringSSL); speaks a transport the mediator does not parse (raw TCP, UDP, QUIC, WebSocket, MCP stdio); spawns a child process | The product must **report this as outside the governed path**, never as governed and never as absence of activity | **Holds only as reporting, not as prevention.** There is no mechanism that prevents A3 on any platform. On Linux with the full stack deployed, some of A3's activity is *Observed*; on macOS and Windows, none of it is |
| **A4 · The misled evaluator** — reads the website, Docs Hub or README and provisions on that basis | Reads only published material; cannot read the source | Every published claim names its platform, its decision timing and its failure posture. A reader must not be able to conclude "eBPF catches bypass attempts on my Mac" or "this cannot be bypassed" from any published sentence | **This artifact exists for A4.** AAASM-5528 removed 69 claims that failed this test; this matrix is the substrate the replacement copy must be written from |

A1 and A3 are the two ends of the same axis, and the difference between them is
**not** the product's controls — it is whether the process cooperates. That is
the structural fact ADR 0002 records and the reason the SDK is not a security
boundary.

## Trust boundaries

| # | Boundary | Trusted side | Untrusted side | Enforced by | Residual |
|---|---|---|---|---|---|
| **T1** | Agent process ↔ `aa-runtime` UDS | `aa-runtime` and everything behind it | The agent process, its SDK, and every field it sends | `aa-runtime` re-scans unconditionally; no "already clean" trust marker exists on the wire, pinned by `aa-runtime/tests/aaasm_2568_gate_verification.rs` | The agent can simply not make the call. Non-participation is not detectable at this boundary |
| **T2** | Agent process ↔ `aa-proxy` | The proxy, out of process | The agent's HTTP request bytes | Out-of-process refusal before dialling upstream | Only for traffic routed to the proxy and only for MitM'd hosts |
| **T3** | `aa-runtime` ↔ `aa-ebpf-loaderd` | The loader daemon, sole `CAP_BPF` holder | `aa-runtime`, which holds no BPF capability | Deliberate privilege separation (AAASM-3603/3604) | The daemon is **not in the release artifact set**, so this boundary does not exist in a released deployment |
| **T4** | Client ↔ `aa-gateway` control plane | Gateway-side policy, registry, budgets, audit | Every client-supplied identity assertion | `credential_token` validation in `check_action`; server-side lineage resolution | Agent-identity possession proof is weaker than it appears — see the identity rows in the matrix |
| **T5** | Runtime audit stream ↔ durable audit store | The sanitizer's output | Every field a sender emits | Write-boundary sanitizer strips banned keys recursively | Emission is best-effort; a dropped entry is indistinguishable from tampering |
| **T6** | Managed-settings file ↔ the dev tool that reads it | The root-owned file's content, read back after write | The user's non-admin account | Filesystem ownership on macOS (B6) | Whether the tool *honours* those keys at runtime is unmeasured — "the open half of AAASM-5298" |

## What this threat model does not replace

- It is **not** the per-release operational threat model
  (`docs/src/security/release-threat-model.md`), which asks "what does *this*
  release change about our exposure?".
- It is **not** the STRIDE catalogue on `docs/src/security/threat-model.md`. That
  page is owned by AAASM-5592/5605 and currently still narrates the superseded
  three-layer model — see [Cross-cutting
  findings](#cross-cutting-findings-reported-not-fixed).
- It **is** the current-state substrate both of those should be reconciled
  against.

---

# The coverage matrix

## How to read it

Each domain carries two tables. **Table 1** answers *what is covered and how
strongly*; **Table 2** answers *what defeats it and what proves it*. Together they
carry all seventeen fields the ticket requires; the
[YAML source](AAASM-5527-capability-coverage-matrix.yaml) carries the same
fields individually split for machine consumption (AAASM-5531).

Column conventions:

- **Coverage** is exactly one [ADR 0033 §6](../docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md) term.
- **Timing** is relative to the action taking effect: `pre` (decision precedes the
  effect), `in-line` (decision precedes egress but the caller has already
  committed), `post` (after the effect), `none`.
- **Mode** carries two facts separated by `·` — enforce-vs-observe, and
  synchronous-vs-best-effort. "Observe · best-effort" is the weakest cell in the
  matrix and appears often; that is the finding, not a formatting artefact.
- **Bnd** is the [boundary class](#boundary-taxonomy) B1–B7.
- **⚠ Q3** — the capability exists but is **off by default**, so what ships is the
  default, not the capability. **⚠ Q4** — the named mechanism does not exist, or
  cannot be reached by a released binary.
- **Level** columns use ADR 0030's ladder for dev-tool rows and ADR 0033 §6
  elsewhere. "Target" is this spike's *recommendation*, not a commitment.

## D1 · Framework tool calls and direct function calls

*(SDK seam rows — see below.)*

## D2 · Host actions: shell, subprocess, filesystem, browser, database

The single most consequential finding in this artifact: **for a native process on
the normal agent path there is no pre-execution mediation of a shell command, a
subprocess spawn, or a host file access on any shipped platform.** The policy
language can express such a rule; nothing in a released build can enforce it.

### D2 · Table 1 — coverage

| ID | Capability / action | Framework · language | Platform · launch · transport | Component | Timing | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|---|---|---|
| **H1** | Shell command / `ProcessExec` by a native agent process | any · any | all · any · n/a | *none on the shipped path* | none | — · — | n/a — nothing runs | **Unmeasured** ⚠ Q4 | — |
| **H2** | Shell command, Linux, eBPF syscall guard armed | any · any | Linux (x86_64 + aarch64) · `AA_EBPF_CONFINE_PID` set **and** policy lowers a non-empty allowlist · syscall | `aa-ebpf-probes` syscall guard via `aa-ebpf-loaderd` | post | enforce-by-kill · async | **fails open** — load/attach failure degrades and the agent proceeds | **Detected** + async process kill — explicitly *not* Denied before execution ⚠ Q3 ⚠ Q4 | B3 |
| **H3** | Process exec observation | any · any | Linux · any · `sched_process_{fork,exec,exit}` tracepoints | `aa-ebpf-probes/src/exec_probes.rs` | post | observe · best-effort | fails open; **no ring-buffer reader is wired** (`aa-runtime/src/runtime.rs:510-512`) | **Unmeasured** ⚠ Q4 | B5 |
| **H4** | File read / write / unlink by a native process | any · any | **Linux x86_64 only** · any · `__x64_sys_*` kprobes | `aa-ebpf/src/kprobe.rs:145-160` (14 targets) | post | observe · best-effort | fails open. The path "blocklist" sets `event.flags = 1` and the syscall proceeds | **Observed** / **Detected** ⚠ Q4 | B5 |
| **H5** | File access by a WASM-marked tool | n/a · WASM guest | all · `aasm sandbox run` or `POST /dispatch_tool` with `ToolKind::Wasm` · in-process | `aa-sandbox` WASI preopen allowlist | pre | enforce · sync | sealed by default (`preopened_dirs` empty) — fail-closed | **Denied before execution** | B3 (of the guest) |
| **H6** | Browser action (Playwright / Selenium / Puppeteer) | any · any | all · any · any | *none* | none | — · — | n/a | **Unmeasured** ⚠ Q4 | — |
| **H7** | Database query | any · any | all · any · any | *none* | none | — · — | n/a | **Unmeasured** ⚠ Q4 | — |
| **H8** | Shell / file rule declared in a tool's own settings file | Claude Code · n/a | macOS · settings write · n/a | `aa-devtool-claude-code` managed settings | pre (by the tool) | enforce-by-the-tool · sync | If the tool ignores the keys, nothing happens and nothing detects it | **Unmeasured** — tool-governance, not a data-path claim | B6 |

### D2 · Table 2 — risk and evidence

| ID | Identity source | Policy context available | Known bypasses | Evidence test / gap | Current | Target |
|---|---|---|---|---|---|---|
| **H1** | none | `GovernanceAction::ProcessExec { command }` (`aa-core/src/policy.rs:229-233`) and `Capability::TerminalExec` (`aa-security/src/policy/capability.rs:42`) are both expressible, evaluated by the engine (`aa-gateway/src/engine/mod.rs:2420-2437`) and carried on the wire (`proto/policy.proto:69,138-139`) — **but only for an action a caller volunteers** | Everything. There is no interception at all | **Gap.** No test can exist for a mechanism that does not exist. Probed with positive control: `McpToolCall` 20 hits vs `PreToolUse`/`pre_tool_use`/`seccomp_filter`/`LD_PRELOAD`/`intercept_exec` **0 hits each** across `aa-proxy/src aa-runtime/src aa-gateway/src aa-cli/src` | **Unmeasured** | Needs a decision, not a ticket — see [Go/No-Go](#go--conditional-go--no-go-per-boundary-class) |
| **H2** | PID in `PID_FILTER`, seeded from `AA_EBPF_CONFINE_PID` | Syscall allowlist lowered from the policy AST (`aa-security/src/policy/ebpf.rs:161,173` → `aa-runtime/src/ebpf_control.rs:36,190`) | Off by default; **`aa-ebpf-loaderd` is not in the release artifact set**; the offending syscall completes before the SIGKILL lands; fork propagation fails open past 1024 PIDs; load-time window runs the confined PID with an empty allowlist | `aa-integration-tests/tests/e2e_ebpf.rs` — **path-gated to `aa-ebpf*/**` changes, so normally SKIPPED on `main`** (`.github/workflows/ci.yml:131-133`); weekly schedule is the standing coverage | **Experimental** | Keep Experimental until AAASM-3872 lands a synchronous deny |
| **H3** | PID / process tree | none consulted | No reader is wired, so events never leave the kernel ring buffer | **Gap** — no evidence test, because nothing consumes the events | **Unmeasured** | Wire the reader or withdraw the capability |
| **H4** | PID | Path blocklist map | x86_64 only — no `__arm64_sys_*` target exists (verified: 16 `__x64_sys_` matches, 0 `__arm64_sys_` in `aa-ebpf/src/kprobe.rs`); observe-only; loaderd unreleased | `aa-integration-tests/tests/e2e_file_monitoring.rs`, same CI gating as H2 | **Observed** (Linux x86_64 only) | State the arch bound wherever file coverage is claimed |
| **H5** | n/a — the guest has no identity | Preopen list, fuel, memory pages, wall clock (`aa-sandbox/src/policy.rs:21-90`) | Not on any agent's normal tool-call path. `aa-proxy` has **no** `aa-sandbox` dependency, contradicting `aa-sandbox/src/lib.rs:10-11` | `aa-integration-tests/tests/e2e_tool_sandbox.rs`, `e2e_tool_sandbox_fs.rs`, `e2e_dispatch_tool_wasm.rs` — these **do** run on `main` | **Denied before execution**, for WASM only | Do not cite as agent-action mediation |
| **H6** · **H7** | — | **Not expressible at all.** There is no `Browser` and no `Database` action kind — verified with positive control: 68 matches for `FileRead\|FileWrite\|Network\|TerminalExec` across `aa-security/src/policy/`, **0** for `Browser`, **0** for `Database` | — | **Gap** | **Unmeasured** | Decide whether to model them as `ToolCall`/`NetworkRequest` or add kinds |
| **H8** | Tool config scope (User / Project / Managed) | `permissions.deny` etc. in the managed document | Whether the tool honours the keys is **unmeasured** — "the open half of AAASM-5298". No `PreToolUse` hook is ever installed (verified: `"permissions"` 15 hits vs `PreToolUse` **0** across `aa-devtool-claude-code/src`) | Read-back of the written file only — evidence of the *write*, never of *enforcement* | **Integrated** (ADR 0030) | `GatewayProtected` requires a core-side adjudication, which this path cannot supply |

> **The `PreToolUse` finding deserves its own sentence.** Claude Code exposes a
> hook that can mediate a `Bash` tool call before it runs — the one mechanism that
> could close H1 for the product's flagship integration — and Agent Assembly never
> registers one. `WRITABLE_KEYS` (`aa-devtool-claude-code/src/managed_settings.rs:96-105`)
> contains the boolean `allowManagedHooksOnly` but never a `hooks` array. This is
> not a limitation of the platform; it is an unimplemented capability.
