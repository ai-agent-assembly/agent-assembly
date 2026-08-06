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

## Row counts

Machine-counted from the [YAML source](AAASM-5527-capability-coverage-matrix.yaml)
(80 rows). Every `coverage` value validates against ADR 0033 §6's closed
eleven-term enum; a value outside it is a schema error, which is the
machine-checkable half of AAASM-5536's V1 gate.

| Coverage (ADR 0033 §6) | Rows |
|---|---|
| **Unmeasured** | 36 |
| **Denied before execution** | 20 |
| **Evaluated** | 6 |
| **Observed** | 5 |
| **Unsupported** | 5 |
| **Redacted** | 4 |
| **Detected** | 2 |
| **Degraded** | 1 |
| **Experimental** | 1 |
| Approval required · Planned | 0 |

**36 of 80 rows are Unmeasured.** That is the headline number, and it is not a
failure of the survey — it is the accurate current state, and the reason the
Epic exists.

| Domain | Rows |
|---|---|
| Network transports (D3) | 13 |
| SDK and framework seams (D1) | 13 |
| Degraded and unavailable modes (D8) | 11 |
| MCP (D4) | 10 |
| Host actions (D2) | 8 |
| Dev-tool launch (D5) | 8 |
| Identity propagation (D7) | 7 |
| Credentials (D6) | 6 |
| Host-level interception per platform (D9) | 4 |

| Boundary class | Rows |
|---|---|
| B3 — one process (all conditional) | 25 |
| B2 — one framework | 6 |
| B5 — one host (**none attained in a released build**) | 5 |
| B6 — one managed device | 4 |
| B1 — one patched function | 3 |
| B7 — opaque SaaS (**not attained**) | 1 |
| B4 — one container | **0** |
| No boundary — the row is a gap | 36 |

**17 of 80 rows are not reachable in a released build** (`reachable_in_release:
false`), and every one of them is an eBPF or `DispatchTool` row. **18 rows
changed on question 3** and **21 on question 4.**

Platform coverage is not a useful count on its own — most rows are
platform-independent gaps — so it is reported per row rather than aggregated.
The four D9 rows are the platform statement: Linux x86_64 and aarch64 have E4
mechanisms that no released binary can load, macOS has E3 plus a managed-settings
route to `HostEnforced` and no E4, and Windows has neither.

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

## D1 · Framework tool calls, SDK adapters and direct function calls

The SDK seam is where the product is strongest against actor A1 and where it is
structurally silent against A3. Three facts govern the whole domain:

1. **Nothing is on before an explicit initialiser call** — `init_assembly()` /
   `initAssembly()` / `assembly.Init()`. Import alone patches nothing in any SDK.
2. **Go additionally requires an explicit `WrapTools`**; `Init` alone wraps nothing.
3. **A deny is only as strong as the seam it sits on**, and the seams differ by
   framework — three distinct kinds coexist: a *raising* wrapper, a *string-returning*
   wrapper, and a *lineage-only* observer that cannot block at all.

### D1 · Table 1 — coverage

| ID | Capability / action | Framework · language | Platform · launch · transport | Component | Timing | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|---|---|---|
| **S1** | Wrapped framework tool call, raising deny | `pydantic_ai`, `google_adk`, `microsoft_agent_framework`, `mcp` (`ClientSession.call_tool`), `langchain` handler · Python | all · in-process after `init_assembly()` · UDS to `aa-runtime` | monkeypatch, deny raised in `_shared/tool_governance.py:225-228` before `invoke_original()` at `:237` | pre | enforce · sync | **fail-closed** — unreachable runtime yields a `_FailClosedInterceptor` that denies every call (`core/runtime_interceptor.py:375-376`, `:521-540`) | **Denied before execution** | B2 |
| **S2** | Wrapped framework tool call, string-returning deny | `crewai`, `openai_agents`, `haystack`, `smolagents`, `agno`, `llamaindex` · Python | as S1 | monkeypatch returning a `[BLOCKED …]` string **before** the original body | pre | enforce · sync | fail-closed | **Denied before execution** | B2 |
| **S3** | Graph / workflow node execution | `langgraph` · Python; `langgraph`, `mastra` · Node | as S1 | monkeypatch of `StateGraph.compile` / `Agent.prototype.generate` | post | **observe · best-effort** | n/a — no decision is taken | **Observed** — the Node hook says so in-tree: *"performs NO in-process tool-governance check, so a policy DENY will NOT block"* (`node-sdk/src/hooks/langgraph.ts:99-108`) | B2 |
| **S4** | LangChain tool call via the **callback handler**, Node | `@langchain/core` · Node | all · auto-detected at `initAssembly()` · — | `assembly-callback-handler.ts:34` `handleToolStart` | post | **observe · best-effort** | n/a | **Observed** — records a `pendingDenials` entry and never throws; the class doc states `@langchain/core` discards the return value so it *"can only observe, never preempt"* (`:13-21`) | B2 |
| **S5** | LangChain tool call via the **explicit wrapper**, Node | `@langchain/core` · Node | all · tools passed as `config.langchain.tools` · — | `wrap-tool-with-assembly.ts:80` replaces `tool.invoke`; throws at `:90` before `originalInvoke` at `:107` | pre | enforce · sync | A **frozen** `invoke` is skipped with a stderr warning and the tool runs **ungoverned** (`:50-58`) | **Denied before execution** — *conditional on the check-capable mode below* | B1 |
| **S6** | Vercel AI SDK / OpenAI Agents tool call, Node | `ai`, `@openai/agents` · Node | all · auto-detected · — | `hooks/ai-sdk.ts:143` throws before `executeOriginal()` at `:161`; `hooks/openai-agents.ts:272-274` returns a deny string before `:287` | pre | enforce · sync | see S7 | **Denied before execution** — *conditional on S7* | B2 |
| **S7** | **The Node default mode routes every check through an allow-all no-op** | all Node frameworks · Node | all · `initAssembly()` with defaults · — | `createClient` (`core/init-assembly.ts:167`): `const mode = config.mode ?? "auto"` (`:171`); only `CHECK_CAPABLE_MODE = "napi-inprocess"` (`:144`) builds a real client (`:201-224`); **every other mode falls through to `createNoopGatewayClient` at `:226`**, whose `check` is `async () => ({ denied: false, pending: false })` (`gateway/client.ts:40`) | pre | **enforce in shape, allow-all in effect** | The tool seams are patched and every verdict is "allow" | **Unmeasured** ⚠ Q3 | — |
| **S8** | Wrapped tool call, Go | any · Go | all · `assembly.Init()` **and** an explicit `WrapTools` · UDS/FFI | `assembly/tool_wrapper.go:83` `runGovernanceGate` returns an error before `t.inner.Call` at `:87` | pre | enforce · sync | **fail-closed and strongest of the three** — `failClosed: true` by default (`defaults.go:14`); a `nil` client denies (`:59-69`); `REDACT`, `UNSPECIFIED` and unknown decision codes all become errors, none silently allows (`ffi_governance_client.go:110,117,127`) | **Denied before execution** | B1 |
| **S9** | Go default build without `-tags aa_ffi_go` + CGO | any · Go | all · default `go build` · — | `internal/ffi/binding_select_fallback.go:5-7` → `fallback_uds_nocgo.go:18-20` returns `statusRuntimeUnavailable` | pre | enforce · sync | Every wrapped tool call **denies** | **Denied before execution** — but by unavailability, not by policy ⚠ Q3 | B1 |
| **S10** | Direct function call that does not pass a patched seam | any · any | all · any · — | *none* | none | — · — | n/a | **Unmeasured** | — |
| **S11** | Framework with no adapter | e.g. any Node framework other than the five detected; any Go framework | all · any · — | *none* | none | — · — | n/a | **Unmeasured** | — |
| **S12** | Raw HTTP, subprocess, filesystem, DB driver, browser automation from inside an SDK-adopting process | any · Python / Node / Go | all · any · — | *none in any SDK* | none | — · — | n/a | **Unmeasured** ⚠ Q4 | — |
| **S13** | The SDK honouring a `Deny` it received | any · Rust core | all · any · UDS | `aa-sdk-client::resolve_decision` | pre | advisory | — | **Evaluated** only ⚠ Q4 | — |

### D1 · Table 2 — risk and evidence

| ID | Identity source | Policy context available | Known bypasses | Evidence test / gap | Current | Target |
|---|---|---|---|---|---|---|
| **S1** · **S2** | `AA_AGENT_ID`, or the SDK's persisted `did:key` identity | Tool name and arguments | Not calling the framework's dispatch; using an unadapted framework; never calling `init_assembly()`; anything in S12 | `aa-integration-tests/tests/e2e_sdk_python.rs`, `e2e_policy_sdk.rs` — both run on `main` (`cargo nextest run --workspace --exclude aa-ebpf`, `.github/workflows/ci.yml:555-586`) | **Denied before execution** (B2) | Hold; document the two deny shapes (see below) |
| **S3** · **S4** | as S1 | Node/tool name for lineage only | The mechanism cannot block; there is nothing to bypass | Present, but they are lineage tests — they cannot evidence prevention | **Observed** | Either add a blocking seam or stop listing these frameworks as governed |
| **S5** · **S6** | as S1 | Tool name and arguments | S7 defeats all of them by default; a frozen `invoke` degrades to ungoverned with only a stderr line | `node-sdk` unit tests; `aa-integration-tests/tests/e2e_sdk_node.rs` | **Denied before execution** only under `mode: "napi-inprocess"` | Make the check-capable mode reachable by default, or fail loudly rather than warn |
| **S7** | — | — | This *is* the bypass, and it is the default. Three partial mitigations exist and none closes it: explicit `enforcementMode: "enforce"` + non-capable mode throws (`:183-190`); explicit `langchain.tools` under a fail-closed posture throws (`:590-605`); **auto-detected frameworks produce a warning only, never a throw** (`:427-465`, `:515-523`), deliberately, to preserve zero-config | **Gap** — no test asserts that the default path enforces, because it does not | **Unmeasured** | [AAASM-4991](https://lightning-dust-mite.atlassian.net/browse/AAASM-4991) already owns this and is still open. **It must be closed before any page claims Node pre-execution denial** |
| **S8** · **S9** | `AA_AGENT_ID` / `did:key` | Tool name and arguments | Not calling `WrapTools`; S12. One residual fail-open: a binding that does not implement `policyQuerier` returns `DecisionAllow` (`internal/ffi/query_policy.go:55-59`) — documented as test bindings only, and both production bridges implement it | `aa-integration-tests/tests/e2e_sdk_go.rs` | **Denied before execution** | Hold. Go is the reference posture the other two should match |
| **S10** · **S11** · **S12** | — | — | This is the residual by construction — B1/B2 do not extend to B3 | **Gap by design.** Recorded so no page can imply otherwise | **Unmeasured** | Never claim beyond B2 for an SDK seam |
| **S13** | — | — | `resolve_decision` has **zero non-test callers in this repository** — verified with a positive control in the same probe: `query_policy` has real callers (`aa-sdk-client/src/client.rs:247` plus CLI and tests), `resolve_decision` matches only its own definition and its `#[cfg(test)]` module. Refusal lives in the out-of-repo FFI shims | **Gap** — the in-repo artifact that would prove the SDK honours a deny does not exist | **Evaluated** (advisory) | Per ADR 0002 this is correct and should stay advisory; the claim wording must match |

> **Two deny shapes inside one SDK.** Six Python adapters return a `[BLOCKED …]`
> string and five raise `PolicyViolationError`. Both prevent the tool body from
> running, so both are *Denied before execution* — but a caller that catches only
> `PolicyViolationError` will silently treat a blocked call as a successful one
> whose result happens to be a string. That is a real integration hazard and it is
> not documented anywhere. Flagged for AAASM-5531 as a manifest field
> (`deny_signal: raise | sentinel_value`).

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

## D3 · Network egress: HTTP, HTTPS, raw TCP, UDP, QUIC, local IPC

`aa-proxy` is the only element that can refuse traffic on its own authority
before it leaves the machine. Its reach is bounded by three independent gates,
each of which must pass: **(a)** the client speaks the HTTP proxy protocol to it,
**(b)** the host is one it MitMs, **(c)** the tool trusts its CA. Under the
shipped defaults, gate (b) admits exactly three hosts.

### D3 · Table 1 — coverage

| ID | Capability / action | Framework · language | Platform · launch · transport | Component | Timing | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|---|---|---|
| **N1** | CONNECT-time egress allow/deny | any · any | Linux + macOS · traffic routed to the proxy · HTTP `CONNECT` | `connect_deny_reason` (`aa-proxy/src/proxy/mod.rs:934`, run at `:1308`) → 403, connection ends | pre | enforce · sync | Both lists are **empty by default** (`AA_PROXY_DENIED_HOSTS`, `AA_PROXY_NETWORK_ALLOWLIST`, `aa-proxy/src/config.rs:75-85`), so the default posture is allow-all **except** the SSRF guard, which denies unconditionally ahead of both | **Denied before execution** ⚠ Q3 | B3 (conditional) |
| **N2** | SSRF guard | any · any | Linux + macOS · routed · CONNECT | `aa-proxy/src/ssrf.rs`, always on | pre | enforce · sync | Always-on; the one network control that is not default-open | **Denied before execution** | B3 (conditional) |
| **N3** | HTTPS payload inspection + credential DLP, built-in LLM hosts | any · any | Linux + macOS · routed **and** CA trusted · TLS MitM, HTTP/1.1 | `handle_llm_mitm` (`aa-proxy/src/proxy/mod.rs:1038`) — `in_tunnel_deny_reason` 403 at `:1066`, `Interceptor` `VerdictDecision::Block` 403 at `:1173` | in-line | enforce · sync | Exactly **three** hosts: `api.openai.com`, `api.anthropic.com`, `api.cohere.com` (`aa-proxy/src/intercept/detect.rs:31-34`). Both refusals are **local policy**, not a gateway decision | **Denied before execution** / **Redacted** | B3 (conditional) |
| **N4** | HTTPS payload inspection, any other host | any · any | as N3 · plus `llm_only=false` **or** an operator `mitm_hosts` entry | `handle_non_llm_mitm` (`:801`) | in-line | enforce · sync | `llm_only` defaults **`true`** (`aa-proxy/src/config.rs:434-439`); `mitm_hosts` is empty by default and matches nothing | **Denied before execution** ⚠ Q3 | B3 (conditional) |
| **N5** | HTTPS to any host not MitM'd | any · any | Linux + macOS · routed · raw TLS relay | `transparent_tunnel` (`:1397`) | — | observe (connection only) · best-effort | Bytes relayed uninspected. `transmission_evidence::forwarded(…)` records *"forwarded, and nothing looked at it — never clean"* (`:1398-1408`) | **connection Observed · payload Unmeasured** | B3 (conditional) |
| **N6** | Model **response** bodies on LLM hosts | any · any | as N3 | *none* — relayed with a raw `tokio::io::copy` (`aa-proxy/src/proxy/mod.rs:1233`) | — | — · — | Responses are never scanned on the LLM path | **Unmeasured** | — |
| **N7** | Plain `http://` request | any · any | Linux + macOS · routed · HTTP/1.1 | plain-HTTP path (`:1485-1560`) — DLP runs | in-line | enforce · sync | **No MCP adjudication on this path** | **Redacted** | B3 (conditional) |
| **N8** | HTTP/2, gRPC, WebSocket over a MitM'd host | any · any | as N3 | *none* | — | — · — | The MitM `ServerConfig` sets **no `alpn_protocols`** (`:1342-1346`), so `h2` is never negotiated; the HTTP/2 preface is rejected as a malformed request line | **Unsupported** on MitM'd hosts; tunnelled and **Unmeasured** elsewhere | — |
| **N9** | Chunked transfer encoding | any · any | as N3 | request: hard reject; response: head parsed, **body left empty** | — | fail-closed (request) / **silent truncation** (response) | A chunked *request* is dropped with no HTTP response (`aa-proxy/src/proxy/http.rs:205-210,266-270`). A chunked *response* on the MCP path is re-serialised with `Content-Length: 0` — see the [cross-cutting findings](#cross-cutting-findings-reported-not-fixed) | **Unmeasured** | — |
| **N10** | Raw TCP that does not speak the proxy protocol | any · any | all · any · TCP | *none* | — | — · — | **No transparent redirect exists** — no iptables, pfctl, TPROXY or `SO_ORIGINAL_DST` (verified with `CONNECT` as positive control: 6 matches, all four redirect terms 0) | **Unmeasured** | — |
| **N11** | UDP, QUIC, HTTP/3 | any · any | all · any · UDP | *none* | — | — · — | Verified repo-wide with `TcpListener` as positive control: 44 matches across `aa-cli`/`aa-proxy`/`aa-gateway`/`aa-runtime`, and **0** for `UdpSocket`, `quinn`, `quic`, `http3` across those plus `aa-core` and `aa-api` | **Unsupported** | — |
| **N12** | Local IPC (Unix domain sockets) between processes | any · any | Unix · any · UDS | *none* — the product's own UDS servers are governed surfaces, not mediated ones | — | — · — | Nothing mediates a third-party UDS conversation | **Unmeasured** | — |
| **N13** | TLS plaintext observation without the proxy | any · any | Linux · any · OpenSSL `SSL_read`/`SSL_write` uprobes | `aa-ebpf-probes/src/ssl_probes.rs:91,123,151` | post | observe · best-effort | Go `crypto/tls`, rustls, statically linked BoringSSL, GnuTLS and NSS expose no such symbols and are not covered (`ssl_probes.rs:17-32`). Events are **not bridged** to the audit pipeline (`aa-runtime/src/runtime.rs:302-305,344-350`) | **Observed** — and, with no bridge, effectively **Unmeasured** downstream ⚠ Q4 | B5 |

### D3 · Table 2 — risk and evidence

| ID | Identity source | Policy context available | Known bypasses | Evidence test / gap | Current | Target |
|---|---|---|---|---|---|---|
| **N1** · **N2** | **None — the proxy has no agent attribution at all.** No peercred, no PID lookup (verified: 0 matches for `peercred`/`SO_PEERCRED`/`peer_pid` in `aa-proxy/src` against 253 `host` matches in `proxy/mod.rs` in the same probe) | Host name only | Unset `HTTPS_PROXY`; a client that ignores proxy env; N10/N11 | `aa-integration-tests/tests/e2e_policy_proxy.rs`, `cli_proxy_remote_bind_refusal.rs` — run on `main` | **Denied before execution** for routed HTTP(S) | State the default-open posture wherever egress control is claimed |
| **N3** · **N4** | as N1 | Request body, headers, host | Everything in N5–N13; removing CA trust; `NODE_TLS_REJECT_UNAUTHORIZED` | `aa-integration-tests/tests/e2e_secret_interception.rs`, `e2e_mcp_redact.rs`; unit tests in `aa-proxy` | **Denied before execution** / **Redacted** | Publish the three-host default explicitly next to every "inspects outbound HTTPS" claim |
| **N5** | as N1 | none for the payload | This is the default path for every host that is not one of three | `transmission_evidence` persists the forwarded-uninspected fact (AAASM-5358) — genuinely good evidence design | **connection Observed · payload Unmeasured** | Keep; this is the model other paths should follow |
| **N6** | as N1 | — | A credential echoed back by a provider is never detected | **Gap** — no response-scanning test on the LLM path, because there is no response scanning | **Unmeasured** | Decide: scan LLM responses, or state the asymmetry publicly |
| **N8** · **N9** | as N1 | — | A tool that requires `h2` cannot use a MitM'd host at all; a chunked response is silently emptied | **Gap.** `aa-proxy/src/proxy/http.rs:747-760` pins the chunked-*request* rejection; nothing pins the chunked-*response* behaviour | **Unsupported** / **Unmeasured** | The chunked-response truncation needs a ticket — it is a correctness bug, not only a coverage gap |
| **N10** · **N11** · **N12** | — | — | These are the transports an adversary A3 picks | **Gap by construction** | **Unsupported** / **Unmeasured** | Never describe the proxy as covering "outbound traffic"; it covers *routed HTTP(S)* |
| **N13** | PID | — | Non-OpenSSL TLS stacks; non-Linux; loaderd unreleased; no audit bridge | `aa-integration-tests/tests/e2e_ebpf.rs` — path-gated, normally skipped on `main` | **Observed** at best | Bridge the events or stop counting TLS observation as coverage |

## D4 · MCP: transports, methods and adjudication

MCP is the domain where the gap between the *named* capability and the
*reachable* one is widest. The product adjudicates exactly **one JSON-RPC method,
on one transport, on one path, only when a gateway endpoint is configured** — and
the most common MCP transport in practice, stdio, is structurally unreachable by a
CONNECT proxy.

### D4 · Table 1 — coverage

| ID | Capability / action | Framework · language | Platform · launch · transport | Component | Timing | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|---|---|---|
| **M1** | MCP `tools/call` adjudication | any MCP client · any | Linux + macOS · routed, CA trusted, **`AA_PROXY_GATEWAY_ENDPOINT` set**, non-LLM MitM'd host · HTTPS POST, HTTP/1.1, explicit `Content-Length` | `evaluate_mcp_request` (`aa-proxy/src/proxy/mod.rs:614`, invoked `:834`) → `aa-gateway` `PolicyService.CheckAction` | pre | enforce · sync | **Fail-closed by default.** `mcp_fail_open` defaults `false` (`aa-proxy/src/config.rs:149,182`). Gateway unreachable at startup ⇒ the proxy **refuses to start** (`proxy/mod.rs:270-286`); per-call failure ⇒ Deny `-32000` (`:666-688`) | **Denied before execution** — the only gateway-bound pre-dial block in the system ⚠ Q3 | B3 (conditional) |
| **M2** | MCP enforcement with no gateway configured | as M1 | `gateway_endpoint` default **`None`** (`aa-proxy/src/config.rs:123-130,179`) | *none* — `evaluate_mcp_request` is reached only via `Some(gw)` (`:832-834`) | — | — · — | MCP enforcement is **dark on a default `aa-proxy` run** | **Unmeasured** ⚠ Q3 | — |
| **M3** | JSON-RPC batch array / malformed envelope carrying `tools/call` | any · any | as M1 | `is_unenforceable_tool_call` (`aa-proxy/src/intercept/mcp.rs:115-130`) | pre | enforce · sync | **Fail-closed** — JSON-RPC `-32600`, upstream never dialled (`proxy/mod.rs:620-631`). This is [AAASM-4070](https://lightning-dust-mite.atlassian.net/browse/AAASM-4070)'s fix | **Denied before execution** | B3 (conditional) |
| **M4** | Every MCP method other than `tools/call` | any · any | as M1 | *none* — the parser returns `None` for any other method (`intercept/mcp.rs:85-87`) | — | — · — | `resources/read`, `prompts/get`, `sampling/createMessage`, `initialize`, all `notifications/*` → `McpEvalOutcome::Skip` → forwarded, subject only to the byte-level credential scanner | **Unmeasured** ⚠ Q4 | — |
| **M5** | MCP over **stdio** (subprocess pipes) | any · any | all · any · pipes | *none, and structurally impossible for a CONNECT proxy* | — | — · — | Verified with positive control: `stdio` = **0** matches in `aa-proxy/src` against `tools/call` = 49 in the same probe. The product **models** stdio servers — `McpServerInfo { name, command, args }` (`aa-core/src/dev_tool.rs:112-121`) — and cannot mediate them | **Unmeasured** ⚠ Q4 | — |
| **M6** | MCP over SSE (`text/event-stream`) | any · any | all · any · SSE | *none* | — | — · — | `text/event-stream` = **0** matches repo-wide. The SSE leg is raw-copied unscanned | **Unmeasured** ⚠ Q4 | — |
| **M7** | MCP over Streamable HTTP | any · any | as M1 | parsed, then **emptied** | — | — · — | A chunked/SSE response is re-serialised with `Content-Length: 0` — the client receives an empty 200. `streamable` = **0** matches repo-wide | **Unmeasured**, and functionally broken ⚠ Q4 | — |
| **M8** | MCP over WebSocket | any · any | all · any · WS | *none* | — | — · — | `Sec-WebSocket` / `101 Switching` = **0** matches in `aa-proxy/src`; no upgrade handling exists | **Unsupported** ⚠ Q4 | — |
| **M9** | MCP on a built-in LLM host | any · any | as N3 | *none* | — | — · — | `handle_llm_mitm` contains **zero** MCP code (`proxy/mod.rs:1038-1241`), so an MCP endpoint on `api.anthropic.com` is DLP-scanned but never adjudicated | **Redacted** only | — |
| **M10** | MCP-server governance by configuration | Claude Code, Copilot, Windsurf · n/a | per-tool · config write · n/a | `enabledMcpjsonServers` / `disabledMcpjsonServers` (`aa-devtool-claude-code/src/lib.rs:385-409`); `chat.mcp.deny`, `chat.mcp.requireApproval` (`aa-devtool-copilot/src/lib.rs:308-321`) | pre (by the tool) | enforce-by-the-tool · sync | Advisory: enforced by the host tool, and any process can launch the server itself | **Unmeasured** — tool-governance, not a data-path claim | B6 (macOS managed only) |

### D4 · Table 2 — risk and evidence

| ID | Identity source | Policy context available | Known bypasses | Evidence test / gap | Current | Target |
|---|---|---|---|---|---|---|
| **M1** | **A constant.** Every MCP `CheckActionRequest` is stamped `agent_id = "aa-proxy"` (`PROXY_AGENT_ID`, `aa-proxy/src/mcp_enforce.rs:48,99-102`) with empty `org_id` / `team_id` / `credential_token` and `caller_agent_id: None` (`:116`) | `tool_name`, `arguments`, `tool_source: "mcp"`, `target_url` — **never agent, team or org** | M2–M9; also: gateway `Decision::Pending` is downgraded to **Deny** (`mcp_enforce.rs:135-144`), so human approval cannot be reached inside the tunnel | `aa-integration-tests/tests/e2e_mcp_interceptor.rs`, `e2e_mcp_redact.rs` — run on `main` | **Denied before execution** | Per-agent MCP policy and per-agent MCP audit **do not exist today** and must not be claimed |
| **M1** (redaction nuance) | as above | — | A gateway `Redact` verdict is bucketed with `Allow` as a forward, and the gateway's `RedactInstructions` are **never replayed field-by-field** (`mcp_enforce.rs:62-75`; `proxy/mod.rs:643-652`). The proxy's own DLP scanner does the redacting instead | This is a documented design decision, not a defect — but it means *"the gateway redacted field X"* is never true | **Redacted** by the proxy scanner | Manifest field for 5531: `redaction_actor: proxy_scanner \| gateway_instructions` |
| **M3** | as M1 | — | A **nested** batch, or a batch whose elements carry `params` without a literal top-level `method`, is not detected — `mentions_tools_call` inspects one level only (`intercept/mcp.rs:128-130`) | **Unit-only.** No wire-level test: `e2e_mcp_interceptor.rs` has no batch case. For a fix to a *bypass* ticket, unit coverage is thin | **Denied before execution** | Add a wire-level negative control under [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532) |
| **M4** | — | — | `resources/read` is a complete data-exfiltration primitive and is adjudicated nowhere | **Gap** | **Unmeasured** | Highest-value MCP follow-up |
| **M5**–**M8** | — | — | Choosing any of these transports removes adjudication entirely | **Gap by construction** | **Unmeasured** / **Unsupported** | [AAASM-5533](https://lightning-dust-mite.atlassian.net/browse/AAASM-5533)-class work; must be stated on every MCP page |
| **M9** | — | — | — | **Gap** | **Redacted** only | — |
| **M10** | tool config scope | server name | Launching the MCP server directly | Read-back of the config write | **Integrated** | Never present config-level MCP disabling as interception |

> **MCP mediation and whole-machine MitM are coupled.** The only supported way to
> get M1 is `aasm proxy start --gateway <url>` or an `aa-runtime`-spawned proxy,
> and both set `AA_PROXY_GATEWAY_ENDPOINT` **and force `AA_PROXY_LLM_ONLY=false`**
> (`aa-cli/src/commands/proxy/start.rs:128-135`; `aa-runtime/src/runtime.rs:246-259`).
> An operator cannot adopt MCP adjudication without simultaneously bringing every
> host on the machine under TLS MitM, with the corresponding latency,
> compatibility and privacy cost. That coupling is a product decision that has
> never been stated publicly, and AAASM-5609's "Choose Your Enforcement Path"
> guide cannot be written honestly without it.

## D5 · Managed dev-tool launch versus unmanaged launch

Five adapters exist; **exactly one can ever be reported above `Integrated`**, and
**two cannot be launched at all**. The rest sit behind `LegacyAdapterShim`, which
declares no interception mechanism and authors no protection test, so ADR 0030's
evidence rules cap them.

### D5 · Table 1 — coverage

| ID | Capability / action | Framework · language | Platform · launch · transport | Component | Timing | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|---|---|---|
| **L1** | Claude Code managed launch | Claude Code · Node | macOS (MVP) · `aasm run` · injects `AA_AGENT_ID`, `AA_TEAM_ID`, the installed launch-env store **including `NODE_EXTRA_CA_CERTS`**, `HTTPS_PROXY`, `HTTP_PROXY` | `aa-devtool-claude-code/src/lib.rs:356-383` | pre (routing established before exec) | enforce · sync | Refuses to launch ungoverned: `resolve_launch_proxy` returns an error unless `--no-proxy` (`aa-cli/src/commands/run.rs:372-388`) | **Denied before execution** for its routed traffic, via `aa-proxy` | B3 (conditional) |
| **L2** | Codex managed launch | Codex · — | macOS + Linux · `aasm run` · injects `AA_AGENT_ID`, `AA_TEAM_ID`, **`HTTPS_PROXY` only** | `aa-devtool-codex/src/lib.rs:281-303` | pre | enforce in shape | **No CA trust is established for the launch.** `NODE_EXTRA_CA_CERTS` count is **0** in this crate against `HTTPS_PROXY` = 1 in the same probe | **Unmeasured** ⚠ Q3 — see the box below | — |
| **L3** | Windsurf managed launch | Windsurf · Electron/Node | macOS + Linux · `aasm run` · `HTTPS_PROXY` only | `aa-devtool-windsurf/src/lib.rs:295-315` | pre | enforce in shape | as L2 — `NODE_EXTRA_CA_CERTS` = **0**, `HTTPS_PROXY` = 3 | **Unmeasured** ⚠ Q3 | — |
| **L4** | Copilot managed launch | GitHub Copilot · VS Code extension | — | `build_launch_command` **always returns `AdapterError::LaunchFailed`** (`aa-devtool-copilot/src/lib.rs:347-359`, pinned by the test at `:530-536`) | — | — · — | There is no managed launch; only a settings write | **Unsupported** (launch) ⚠ Q4 | — |
| **L5** | SaaS / opaque agent | Claude.ai and siblings · — | — | `aa-devtool-saas/src/adapter.rs:93-100` also always errors; `supports_managed_settings: false` (`:71`); **not registered in `SUPPORTED_TOOLS` at all** (`aa-devtool/src/registry.rs:39`) | — | observe · best-effort | Hard-capped at `L1Observe`, documented as "L2/L3 unreachable" (`:119-122`). It is an audit-ingest adapter, not a launcher | **Observed** at best | B7 — and it does not attain it |
| **L6** | Unmanaged launch (the user starts the tool directly) | any · any | all · direct · — | *none* | — | — · — | Not detectable. Stated in-tree as an unobservable bypass (`aa-devtool-claude-code/src/bypass.rs:228-235`) | **Unmeasured** | — |
| **L7** | Settings-layer governance surviving an unmanaged launch | Claude Code · — | macOS · root-owned `/Library/Application Support/ClaudeCode/managed-settings.json` · — | `managed_settings.rs:1063-1079` — `disableBypassPermissionsMode`, `allowManagedPermissionRulesOnly` | pre (by the tool) | enforce-by-the-tool · sync | Survives an unmanaged launch because the tool reads the file itself. Whether it *honours* the keys is unmeasured | **Unmeasured** (data path); ADR 0030 `HostEnforced` reachable on the *tool-governance* axis | **B6** |
| **L8** | `aasm run --no-proxy` | any · any | all · explicit flag · — | `resolve_launch_proxy` (`aa-cli/src/commands/run.rs:372-388`) prints a warning and returns `None` | — | — · — | Guarded: refused where a managed receipt or a managed-settings file says the host runs managed (`run.rs:894-903`). Ambient `HTTPS_PROXY`/`HTTP_PROXY` are **removed**, not inherited, when proxy is `None` and `no_proxy` is false (`:329-333`) | **Unmeasured**, and explicitly announced as such | — |

> **A measured defect class, fixed for one adapter and still open for two.**
> `aa-devtool-claude-code/src/lib.rs:337-346` records what AAASM-5276 measured
> against the real `claude 2.1.220` binary: this method *"used to inject
> `HTTPS_PROXY` and nothing else, so the handshake failed and the tool's traffic
> was never inspected. **Silently**: a proxy that cannot terminate TLS still lets
> the connection through."* **`aa-devtool-codex` and `aa-devtool-windsurf` still
> inject `HTTPS_PROXY` and nothing else.** Whether their handshake succeeds
> depends on whether their TLS stack honours the OS trust store — which the
> proxy does attempt to populate on macOS and on Linux via `aasm proxy install-ca`
> — and a Node/Electron runtime does **not** consult that store by default, which
> is precisely why `NODE_EXTRA_CA_CERTS` exists. No evidence test covers either
> adapter's launch. The honest state for L2 and L3 is therefore **Unmeasured**,
> not "governed", and neither may be listed as a protected integration until a
> protection probe adjudicates one. **Needs a new ticket** — see [Gap-to-ticket
> mapping](#gap-to-ticket-mapping).

### D5 · Table 2 — risk and evidence

| ID | Identity source | Policy context available | Known bypasses | Evidence test / gap | Current (ADR 0030) | Target |
|---|---|---|---|---|---|---|
| **L1** | `AA_AGENT_ID` + `did:key` registration over gRPC | Full: proxy DLP, MCP adjudication if a gateway is configured, managed settings | The eleven-item Claude Code list in `docs/src/devtools/limitations.md:69-84`; everything in D2, D3, D4 | `aa-integration-tests/tests/cli_run_claude_governed_launch.rs`, `cli_run_claude_launch_env.rs`, `claude_code_integration_lifecycle.rs`, `conformance_claude_code.rs` — run on `main` | **`HostEnforced` reachable** — the only adapter for which it is (`lifecycle.rs:1354`) | Hold; close the AAASM-5298 open half |
| **L2** · **L3** | `AA_AGENT_ID` | Whatever the proxy sees — which may be nothing | No CA trust ⇒ possibly no inspection at all, silently; plus all of L1's | **Gap — no launch evidence test for either adapter** | **Hard-capped at `Integrated`** by `LegacyAdapterShim` (`aa-core/src/integration/shim.rs:29-33`) | Do not raise the cap until a protection probe adjudicates a launch |
| **L4** | — | Settings write only (`github.copilot.enable`, `chat.tools.autoApprove`, `chat.mcp.deny`, `chat.mcp.requireApproval`) | Editing the settings back | Read-back only | **Hard-capped at `Integrated`** | Correct as-is; never describe Copilot as launch-governed |
| **L5** | — | Whatever the SaaS surface exposes | Everything — the operator does not control execution | Webhook ingest only (`aa-api/src/routes/devtools/mod.rs:57-59`) | **`L1Observe`** | Correct as-is. This is the honest B7 answer |
| **L6** · **L8** | — | — | This is the bypass | `aa-devtool-claude-code/src/bypass.rs` names what is and is not detectable, which is the right design | **Unmeasured** | Keep announcing it |
| **L7** | file ownership | managed document keys | A local administrator; the tool ignoring the keys | Read-back of the written file, never observed enforcement — "the open half of AAASM-5298" (`managed_settings.rs:50-57`) | **`HostEnforced`** on the tool-governance axis | Do not let this rung imply data-path prevention |

## D6 · Credential and secret boundary

Two distinct mechanisms are both called "credential injection" in this codebase
and in public copy. **One is dead; the other ships and works.** Conflating them
is what produced the AAASM-5528 W16/W17 over-claims, and separating them is
required before AAASM-5609 writes anything about secrets.

### D6 · Table 1 — coverage

| ID | Capability / action | Framework · language | Platform · launch · transport | Component | Timing | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|---|---|---|
| **C1** | Outbound credential scan + redact on an inspected request | any · any | Linux + macOS · routed + CA trusted · MitM'd host | `aa-security` scanner via `intercept_request` | in-line | enforce · sync | Default is **`RedactOnly`** — forward with the secret redacted, not block (`aa-proxy/src/config.rs:16-27`, `#[default]` on `RedactOnly` at `:23-24`). `Block` is opt-in; `AlertOnly` forwards the credential **unmodified** and, per E4, raises no alert | **Redacted** ⚠ Q3 | B3 (conditional) |
| **C2** | Credential substitution at egress — the real provider key never enters the agent | any · any | Linux + macOS · `AA_PROXY_PROVIDER_KEYS=host=key` set in the proxy's environment · MitM'd LLM host | `CredentialStore::from_env` (`aa-proxy/src/credentials.rs:198`) → `authorization_for` (`:238`) → `serialize_http_request_with_auth` (`aa-proxy/src/proxy/http.rs:353`), which **strips the agent's own `Authorization` / `x-api-key`** at `:371-373` and appends the operator's real key at `:379-383` | in-line | enforce · sync | Empty by default; a malformed entry is skipped with a log that never echoes key material (`credentials.rs:213-218`) | **Denied before execution** for the agent's own credential reaching upstream ⚠ Q3 | B3 (conditional) |
| **C3** | Credential injection via `SecretsService.DispatchTool` | any · any | — | `proto/secrets.proto:12`; `aa-api/src/routes/dispatch.rs:125` | — | — · — | **Unreachable.** Both production constructions instantiate a fresh empty `InMemorySecretsStore` (`aa-api/src/state.rs:449`; `aa-gateway/src/server.rs:693`); no registration route; no `aasm secrets` command; every `${NAME}` resolves to `UnknownPlaceholder` | **Unmeasured** ⚠ Q4 | — |
| **C4** | Model **response** credential scanning | any · any | — | *none* on the LLM path (raw `tokio::io::copy`, `aa-proxy/src/proxy/mod.rs:1233`); present on the MCP path (`redact_response_body`) | — | — · — | Asymmetric by path | **Unmeasured** (LLM) / **Redacted** (MCP) | — |
| **C5** | Environment inheritance by `aasm run` | any · any | all · `aasm run` · — | `std::env::vars().collect()` (`aa-cli/src/commands/run.rs:306`) | — | — · — | The child receives **the entire parent environment**, so a shell or file tool in the agent can read any credential the operator exported. The masking helper is used only for `--dry-run` preview text | **Unmeasured** | — |
| **C6** | Scanner recall | any · any | all · — · — | `aa-security/src/scanner.rs` | in-line | detect · sync | Bounded to the pattern set: **no Stripe detector** exists; the OpenAI detector keys on `sk-` while Stripe uses `sk_`. A secret split by a separator (`中`, emoji, space, tab, newline) scans clean — accepted residual (AAASM-5368) | **Detected**, bounded | B3 (conditional) |

### D6 · Table 2 — risk and evidence

| ID | Identity source | Policy context available | Known bypasses | Evidence test / gap | Current | Target |
|---|---|---|---|---|---|---|
| **C1** | none (proxy has no agent attribution) | request body and headers | Every non-inspected path in D3; `AlertOnly`; C6's recall bound | `aa-integration-tests/tests/e2e_secret_interception.rs` — runs on `main` | **Redacted** | State the `RedactOnly` default wherever DLP is claimed |
| **C2** | none | host → key mapping | Only the three MitM'd LLM hosts (or `mitm_hosts`); the operator must set the env var; the agent can still egress on any path in D3 | **Gap** — unit tests exist in `aa-proxy/src/credentials.rs:307-322`; no end-to-end test proves the substitution reaches upstream | **Denied before execution** (opt-in) | **This capability was under-recorded.** A narrow, true version of "the real key never enters the agent" exists and 5609 may state it *with its four conditions named* |
| **C3** | — | — | — | `aa-integration-tests/tests/common/mod.rs:246` registers a secret in a **test helper only** | **Unmeasured** | [AAASM-5631](https://lightning-dust-mite.atlassian.net/browse/AAASM-5631) owns the decision |
| **C4** · **C5** · **C6** | — | — | as stated | `aa-security/src/scanner.rs:1071-1092,3012-3030` pins the separator residual | **Unmeasured** / **Detected** | C5 warrants a ticket: whole-environment inheritance defeats C2's benefit for any agent with a shell tool |

## D7 · Identity propagation: agent, sub-agent, process tree, tenant

### D7 · Table 1 — coverage

| ID | Capability / action | Component | Mode | Failure posture | Coverage | Bnd |
|---|---|---|---|---|---|---|
| **I1** | Agent identity — Ed25519 `did:key` with a possession proof | Identity key is **random CSPRNG and persisted owner-only** (`aa-sdk-client/src/identity_store.rs`: `O_EXCL`, `0600`, symlink/uid/mode validation at `:218`; entry points `load_or_enroll` `:344`, `enroll` `:402`, `rotate` `:439`, `revoke` `:479`). Gateway enforces `enforce_did_key_binding` (`aa-gateway/src/service/lifecycle_service.rs:232-239`) and `verify_possession_proof` over a **server-issued single-use nonce** (`:241-259`, consumed `:454-457`) | enforce · sync | Registration refuses rather than proceeding under an unprovable identity | **Evaluated** — genuinely strong ✅ **Q4 changed the answer in the product's favour** | B3 |
| **I2** | Transport key for the runtime UDS handshake | Still `SHA-256(agent_id)` (`aa-sdk-client/src/keypair.rs:107-131`; recomputed at `aa-runtime/src/ipc/handshake.rs:29,51`) | — | **Deliberately non-secret.** The trust boundary there is the socket's `0600` mode plus peercred UID, not the signature | **Evaluated** — correct by design, provided the docs never call it an authentication key | B3 |
| **I3** | Sub-agent / delegation lineage | First-class and **server-computed**: `parent_agent_id`, `depth`, `root_agent_id`, `delegation_reason`, `spawned_by_tool` (`aa-core/src/agent.rs:52-71`); derived at registration with the parent required to be already registered (`lifecycle_service.rs:477-497`) | enforce · sync | Invalid parent ⇒ `Status::invalid_argument` | **Evaluated** — a genuine strength, and under-advertised | B3 |
| **I4** | Process-tree identity across fork/exec | **No agent id crosses fork/exec.** Verified with positive control: `agent_id` = **0** matches in `aa-ebpf-probes/src/exec_probes.rs` and `aa-ebpf-common/src/exec.rs`, against `pid` = 52 and 10 matches respectively in the same probe. Only pid ancestry propagates (`PARENT_TGID`, `EXEC_PID_FILTER`) | observe · best-effort | Userspace correlation is pid-only (`aa-runtime/src/correlation/pid.rs:28-81`) — and the bridge that feeds it **hardcodes `pid: 0`** (`aa-runtime/src/correlation/mod.rs:47-49`, `TODO(AAASM-150)`), so pid-family correlation is inert on that path | **Unmeasured** ⚠ Q4 | — |
| **I5** | Tenant / org isolation | Carried consistently on the wire (`ProtoAgentId`, `VerifiedCaller`, `AgentRecord.org_id`, audit lineage). **Enforced per call site, not at the storage layer**: `AgentFilter.org_id` is an `Option` applied only when the caller supplies it (`aa-gateway/src/storage/postgres.rs:240-243`, `sqlite.rs:343-346`), and `get_agent` by id has **no org predicate at all** (`postgres.rs:499-508`). The DB-backstopped path is Postgres RLS, and only for the `_for_tenant` methods (`aa-storage-postgres/src/audit_sink.rs:56-74`). `aa-storage-memory` has **zero** `org_id` references across all nine source files, against 85 in `aa-storage-postgres/src/user_store.rs` as positive control | mixed | `TenancyMode` defaults to `Untenanted` (`aa-gateway/src/server.rs:657-663`) | **Evaluated**, unevenly ⚠ Q3 | B3 |
| **I6** | Agent attribution of proxy traffic | **None.** `PROXY_AGENT_ID = "aa-proxy"` constant on every MCP `CheckActionRequest` (`aa-proxy/src/mcp_enforce.rs:48,99-102`); `ProxyEvent.agent_id` is hardcoded `None` at the production construction site (`aa-proxy/src/proxy/mod.rs:1081`); no peercred or PID lookup exists | — | Logs render the agent as `<unknown>` | **Unmeasured** ⚠ Q4 | — |
| **I7** | Gateway agent-plane authentication | **`PolicyService` and `AgentLifecycleService` are mounted behind `enrich_interceptor`, which returns `Ok(req)` unconditionally when no valid token is present** (`aa-gateway/src/iam/grpc_auth.rs:150-161`; wiring `aa-gateway/src/server.rs:719-745` for TCP and `:864-880` for UDS). `AuditService`, `ApprovalService`, `TopologyService`, `SecretsService` and `InvalidationService` use the fail-closed `auth_interceptor` (`:122-141`). `PolicyService` compensates in-body via `apply_authoritative_tenancy` (`policy_service.rs:398-425`) — but **only when a credential token resolves**; a tokenless call keeps the client-supplied org/team | — | By design for bootstrap: `Register` is documented as an unauthenticated bootstrap endpoint (`aa-sdk-client/src/identity_store.rs:5-9`) | **Evaluated**, with a stated bootstrap exposure ⚠ Q3 | B3 |

### D7 · Table 2 — risk and evidence

| ID | Known bypasses | Evidence test / gap | Current | Target |
|---|---|---|---|---|
| **I1** · **I2** · **I3** | Registration is reachable by anyone who can reach the agent plane (I7), so identity is *provable* but the plane is *open* | `aa-integration-tests/tests/e2e_a2a_identity.rs`, `native_auth_gating.rs`, `api_auth_matrix.rs`; `aa-gateway/tests/lifecycle_service_test.rs`. **Residual smell:** `aa-cli` registration tests and the gateway lifecycle tests still mint registration keys with `derive_transport_key(agent_id)` (`aa-cli/src/commands/run_registration.rs:583,668`), the exact derivation AAASM-5332 removed from the production path — so the fixtures exercise a derivable key | **Evaluated** | Keep. Advertise I3; it is stronger than anything published about it |
| **I4** | Any child process | **Gap** — a hardcoded `pid: 0` cannot be tested into correctness | **Unmeasured** | Wire the pid through or withdraw process-tree attribution claims |
| **I5** | A caller that omits `org_id` on a filtered read; `get_agent` by id; any memory-backend deployment | `aa-integration-tests/tests/e2e_org_isolation.rs`, `api_iam.rs`; `aa-api/src/ws/tenant.rs:10-25` is fail-closed for untagged events | **Evaluated**, unevenly | Push org scoping into the storage trait rather than the call sites |
| **I6** | — | **Gap** | **Unmeasured** | [AAASM-5533](https://lightning-dust-mite.atlassian.net/browse/AAASM-5533) owns "real agent identity binding" and this is its concrete requirement |
| **I7** | An unauthenticated caller reaching the agent plane can register and can submit policy queries carrying its own org/team | `aa-api` is uniformly gated by contrast (`aa-api/src/routes/mod.rs:281`) | **Evaluated** | Document the bootstrap exposure explicitly; it is defensible but must not be described as "authenticated" |

## D8 · Degraded and unavailable modes

Failure posture is a security property, not an operational footnote. **The
product's fail-closed choices are good where they exist and are not uniform**;
three silent fail-opens sit next to each other, and the mechanism that is supposed
to make degradation visible is emit-only.

| ID | Scenario | Posture | Evidence | Coverage |
|---|---|---|---|---|
| **G1** | `aa-runtime` → gateway unreachable on a policy query | **Fail-closed by default** — `Deny`, reason *"gateway unreachable; denied by fail-closed policy"* (`aa-runtime/src/pipeline/mod.rs:467-486`); timeouts identical (`:648-651`); `AA_GATEWAY_FAIL_CLOSED` unset ⇒ `true` (`aa-runtime/src/config.rs:306-310`). Unknown gateway decision codes collapse to `Deny` (`:657-668`) | Pinned by `aa-integration-tests/tests/e2e_runtime_gateway_deny.rs` | **Denied before execution** ✅ |
| **G2** | `aa-runtime` with **no gateway configured**, or `fail_closed=false` | **Fail-open** — falls through to local evaluation whose terminal default is **Allow** (`pipeline/mod.rs:527-536`); `GatewayOutcome::NoClient` takes the same path | — | **Unmeasured** ⚠ Q3 |
| **G3** | `aa-proxy` → gateway unreachable, MCP | **Fail-closed at both points** — refuses to start (`proxy/mod.rs:270-286`); per-call Deny `-32000` (`:666-688`) | `aa-proxy/src/config.rs:957-966` pins the default | **Denied before execution** ✅ |
| **G4** | Credential/DLP default | **Fail-open** — `RedactOnly` forwards | `aa-proxy/src/config.rs:888` | **Redacted** ⚠ Q3 |
| **G5** | SDK cannot reach the runtime UDS | Python **fail-closed** (`_FailClosedInterceptor` denies every call); Node **fail-closed only under an explicit enforce posture**, and defeated by S7 in the default mode; Go **fail-closed** | per-SDK unit tests | mixed |
| **G6** | eBPF load/attach failure | **Fail-open, soft degrade** — warn, emit `LayerDegradation`, continue (`aa-runtime/src/ebpf_control.rs:204-213`, `:378-384`) | — | **Degraded** |
| **G7** | eBPF policy file unreadable or unparseable | **Silent fail-open to an empty rule set** — no kernel rules at all (`aa-runtime/src/ebpf_control.rs:190-201`), with no `LayerDegradation` raised | **Gap** | **Unmeasured** ⚠ Q3 |
| **G8** | Gateway policy load or schema failure | **Fail-closed at boot** — server startup aborts (`aa-gateway/src/server.rs:617-621`, `:777-781`); `aa-runtime` exits `1` on policy parse failure | — | **Denied before execution** ✅ |
| **G9** | Budget state unreadable or corrupt | **Silent fail-open — the cap resets to zero spend** (`aa-gateway/src/server.rs:155-163`, `load_from_disk(...).unwrap_or_else(...)`); write failure is an `eprintln!` and continue (`aa-gateway/src/budget/persistence.rs:85-86`). Budget never queries the control-plane DB — verified with positive control: `budget` in `aa-gateway/src/storage/*.rs` = 1 unrelated hit, `audit` = 57 in the same file | **Gap** | **Unmeasured** ⚠ Q3 |
| **G10** | Audit emission failure | **Fail-open** — `try_send` full ⇒ warn + `audit_drops` counter; closed ⇒ error; either way the RPC **returns `event_id` and reports success** (`aa-gateway/src/service/audit_service.rs:175-187`). The hash chain advances *before* the send (`:172`), so a dropped entry leaves a permanent chain gap indistinguishable from tampering | [AAASM-5626](https://lightning-dust-mite.atlassian.net/browse/AAASM-5626) owns this | **Unmeasured** |
| **G11** | Degradation visibility | **Emit-only.** Three producers (`aa-runtime/src/runtime.rs:280-298`, `:571-583`, plus `ebpf_control.rs:211`), all using `let _ = broadcast_tx.send(...)`; a WS payload type (`aa-api/src/models/ws_payloads.rs:92-100`); and **no renderer**. Verified with positive control: `LayerDegradation` appears in exactly one dashboard file, `dashboard/src/api/events.ts` (a type declaration, 3 mentions), against `policy_violation` = 110 mentions across real dashboard feature code. `degraded_layers` = **0** matches in `aa-cli/src`. The `/health` `degraded_layers` field is a snapshot moved in once at boot (`aa-runtime/src/runtime.rs:1180-1188`) and never updates; `status` is the hardcoded literal `"healthy"` (`aa-runtime/src/health/mod.rs:50`) | **Gap** | **Unmeasured** ⚠ Q4 |

> **G11 fails an Epic exit criterion outright.** AAASM-5526 requires that
> *"Runtime / proxy / adapter degradation is visible and cannot be reported as
> protected without evidence."* The first half does not hold today: a degradation
> is emitted into a broadcast channel whose result is discarded, typed in the
> dashboard's API surface, and rendered nowhere. [AAASM-5535](https://lightning-dust-mite.atlassian.net/browse/AAASM-5535)
> is already In Progress and owns exactly this.

## D9 · Host-level interception, per platform (E4)

This table does not extend ADR 0033 §5.3; it re-verifies it and adds the release
artifact fact, which §5.3 does not state.

| ID | Platform | E3 transport mediation | E4 host-level interception | Coverage | Bnd |
|---|---|---|---|---|---|
| **P1** | **Linux x86_64** | `aa-proxy`; CA via `sudo aasm proxy install-ca` (`aa-cli/src/commands/proxy/ca.rs:150-188`) | eBPF TLS uprobes, file-I/O kprobes (14 `__x64_sys_*` targets), exec tracepoints — all observe-only; syscall guard as an opt-in **asynchronous kill** | **Observed** / **Detected**; the guard is **Experimental** ⚠ Q3 ⚠ Q4 | B5 in principle, **unattainable in a released build** |
| **P2** | **Linux aarch64** | `aa-proxy` | eBPF TLS + exec only. **No file-I/O coverage** — 0 `__arm64_sys_*` targets against 16 `__x64_sys_` in `aa-ebpf/src/kprobe.rs` | **Observed** (partial) | as P1 |
| **P3** | **macOS** | `aa-proxy`; System Keychain trust **attempted automatically at proxy start**, gated only on whether the certificate is already installed, requiring admin authorization, and **a refused prompt fails proxy startup** (`aa-proxy/src/lib.rs:62-69`; `tls/keychain.rs:16,18,23-32`) | **None.** Endpoint Security and Network Extension are explicit non-goals, pinned by a test asserting the literal limitation string (`aa-cli/src/commands/integrations/model.rs:1200,1204`) | E3 **Denied before execution**; E4 **Unsupported** — but macOS is the **only** platform where ADR 0030's `HostEnforced` rung is reachable, via the root-owned managed-settings route | **B6** (managed-settings route only) |
| **P4** | **Windows** | **None** — `aa-proxy`'s accept loop uses `tokio::signal::unix` unconditionally, so the crate has no Windows build path | **None** — no ETW, WFP or minifilter code | **Unsupported** | — |

> **The finding ADR 0033 §5.3 does not carry: E4 is unreachable in a released
> build on every platform.** `aa-ebpf-loaderd` is the sole `CAP_BPF` holder and
> the only way to load any probe, and it is **explicitly excluded from the release
> artifact set** — `scripts/check-release-completeness.sh:45` names it in a
> comment as *"eBPF loader daemon: not part of the release"* and `:58` lists it in
> `UNRELEASED_BINARIES`. Verified with a positive control in the same probe:
> `aa-ebpf-loaderd` returns zero matches in `.github/workflows/release.yml` while
> `aasm` returns dozens. `RELEASE_BINARIES` is `aasm aa-gateway aa-runtime
> aa-proxy aa-api-server` (`:25`).
>
> Therefore **a released deployment silently degrades to E2 + E3 only**, and every
> row in P1 and P2 is *source-tree capability*, not *shipped capability*. This is
> [AAASM-5640](https://lightning-dust-mite.atlassian.net/browse/AAASM-5640), and
> it is the single most consequential Q4 result in this survey: it means that
> **for a user of any released build, Agent Assembly has no host-level
> interception on any platform.**

---

# Bypass catalogue

The demonstrated/inferred split is adopted from
[`docs/src/devtools/limitations.md:49-84`](../docs/src/devtools/limitations.md),
which established it for Claude Code. It is generalised here to the whole
product. The split matters because **a demonstrated bypass is a measurement and
an inferred one is a documented belief**, and a reader deciding how much to trust
the product needs to know which is which.

Neither list is exhaustive. **"No finding" is not "no bypass."**

## Demonstrated — asserted positively by a test or a measurement

| # | Bypass | Where it was measured |
|---|---|---|
| **D-a** | `ANTHROPIC_BASE_URL` pointed at any endpoint removes the product from the path and the raw secret arrives | AAASM-5276 harness, against the real `claude 2.1.220` binary and an emulated client |
| **D-b** | Launching the tool outside the managed path (no `HTTPS_PROXY`) is unprotected | AAASM-5276 harness |
| **D-c** | `Observe` / `AlertOnly` forwards the secret unchanged | AAASM-5276 harness. Correct behaviour, and the reason observe-only must never render as protection |
| **D-d** | Injecting `HTTPS_PROXY` without CA trust leaves traffic uninspected — **silently**, because a proxy that cannot terminate TLS still lets the connection through | Measured for Claude Code and fixed there; recorded verbatim at `aa-devtool-claude-code/src/lib.rs:337-346`. **Still the live behaviour of `aa-devtool-codex` and `aa-devtool-windsurf`** |
| **D-e** | A JSON-RPC batch array carrying `tools/call` evades single-envelope MCP adjudication | AAASM-4070; now fail-closed and pinned by unit tests at `aa-proxy/src/intercept/mcp.rs:222-272` |
| **D-f** | A host classified `Unknown` under `llm_only` takes the transparent raw tunnel, reaching the provider with no scan, redact or audit — including case and trailing-dot FQDN variants before AAASM-3983 canonicalised them | `aa-proxy/src/intercept/detect.rs:20-27`; canonicalisation pinned at `aa-proxy/src/proxy/mod.rs:1300-1304` |
| **D-g** | A secret split by a separator (`中`, emoji, space, tab, newline) scans clean | `aa-security/src/scanner.rs:1071-1092,3012-3030` (AAASM-5368), accepted residual |

## Inferred — documented, not measured

Grouped by the boundary each defeats.

| Boundary defeated | Inferred bypasses |
|---|---|
| **The managed launch (L1–L8)** | `--dangerously-skip-permissions` · `defaultMode: bypassPermissions` · `--bare` · unsetting the proxy env in the shell · repointing `CLAUDE_CONFIG_DIR` · symlinking `.claude` · replacing the binary · calling the provider API directly with the user's own key · switching provider (`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX`) · running a pre-managed-settings release · a hook exiting `1` instead of `2` |
| **The SDK seam (S1–S13)** | Never calling `init_assembly()` / `initAssembly()` / `assembly.Init()` · not calling `WrapTools` in Go · using an unadapted framework · calling the underlying function directly rather than through the framework's dispatch · relying on the Node default mode, which routes through the allow-all no-op (S7) · a frozen `invoke` that the Node wrapper skips with a stderr warning |
| **The transport mediator (N1–N13)** | Raw TCP that does not speak the proxy protocol · UDP / QUIC / HTTP-3 · WebSocket · HTTP/2 to a MitM'd host · a chunked request (dropped, not inspected) · local IPC · any host outside the three MitM'd by default · a TLS stack the uprobes do not hook |
| **MCP adjudication (M1–M10)** | stdio · SSE · Streamable HTTP · WebSocket · any method other than `tools/call` — `resources/read` most sharply, since it is a complete data-exfiltration primitive · a **nested** batch, or a batch whose elements carry `params` without a literal top-level `method` (`mentions_tools_call` inspects one level only) · running the MCP server yourself rather than via the tool's config · an MCP endpoint on a built-in LLM host, which `handle_llm_mitm` never adjudicates |
| **Host-level interception (P1–P4)** | Everything, on every platform, in every released build — the loader daemon does not ship |
| **The evidence pipeline (G1–G11)** | An audit entry dropped under load is indistinguishable from a tampered one · a degradation is emitted and never rendered · budget state corruption silently resets the cap · an unreadable eBPF policy silently yields an empty rule set |

## Which of these the product can see

Detection is not prevention, and neither is a bypass a product failure — but a
bypass the product cannot even *see* is materially worse than one it names.

| Class | Detected? | Where |
|---|---|---|
| Claude Code settings / env / launch-flag bypasses (`bypassPermissions`, `ANTHROPIC_BASE_URL`, `CLAUDE_CODE_USE_BEDROCK`/`_VERTEX`, `NODE_TLS_REJECT_UNAUTHORIZED`, `--dangerously-skip-permissions`, `--bare`) | **Yes** | `aa-devtool-claude-code/src/bypass.rs` — a `status`-time configuration read, reported and level-lowering |
| Unmanaged launch of any tool | **No** | Nothing is injected, so there is nothing to observe. Named in-tree as unobservable (`bypass.rs:228-235`) |
| Every bypass in the SDK, transport, MCP, host-level and evidence rows above | **No** | No detector exists for any of them |

There is **no process watcher** for an unmanaged tool invocation on any platform.

---

# Where questions 3 and 4 changed the answer

This is the section the method exists to produce. Twelve rows changed; three
changed in the product's favour.

## Question 3 — the capability exists but is off by default

| Row | Named capability | What actually ships |
|---|---|---|
| **N1** | Network egress allow/deny | Both `AA_PROXY_DENIED_HOSTS` and `AA_PROXY_NETWORK_ALLOWLIST` are **empty**: default-open, with only the always-on SSRF guard |
| **N4** | HTTPS payload inspection | `llm_only=true` and empty `mitm_hosts`: **three hosts**, everything else transparently tunnelled |
| **M2** | MCP adjudication | `gateway_endpoint` defaults to `None`: **entirely dark** on a default `aa-proxy` run |
| **H2** / **P1** | eBPF syscall guard | Off unless `AA_EBPF_CONFINE_PID` names a PID **and** policy lowers a non-empty allowlist |
| **C1** | Credential DLP | `RedactOnly` (forward redacted), not `Block` |
| **C2** | Credential substitution at egress | Empty unless the operator sets `AA_PROXY_PROVIDER_KEYS` |
| **S7** | Node pre-execution denial | `mode: "auto"` routes every check through the allow-all no-op; only `napi-inprocess` is check-capable |
| **S9** | Go enforcement | The default build without `-tags aa_ffi_go` + CGO denies **everything** — fail-closed, but not the advertised behaviour either |
| **G2** | Runtime policy gate | With no gateway configured, local evaluation's terminal default is **Allow** |
| **G7** / **G9** | eBPF rules; budget caps | An unreadable file silently yields an empty rule set / a zero-spend reset, with no degradation signal |
| **I5** / **I7** | Tenant isolation; agent-plane auth | `TenancyMode` defaults to `Untenanted`; `PolicyService` and `AgentLifecycleService` sit behind a never-rejecting `enrich` interceptor |
| **L2** / **L3** | Codex and Windsurf "managed launch" | `HTTPS_PROXY` with no CA trust — the measured D-d failure mode, unfixed |

## Question 4 — the mechanism does not exist, or a released binary cannot reach it

| Row | Named capability | Verified state |
|---|---|---|
| **P1**–**P4** | Host-level interception on any platform | **`aa-ebpf-loaderd` is not in the release artifact set.** E4 is unreachable in every released build, on every platform ([AAASM-5640](https://lightning-dust-mite.atlassian.net/browse/AAASM-5640)) |
| **C3** | Credential injection via `DispatchTool` | Nothing can populate the secrets store; no registration route; no CLI command ([AAASM-5631](https://lightning-dust-mite.atlassian.net/browse/AAASM-5631)) |
| **M5**–**M8** | MCP over stdio / SSE / Streamable HTTP / WebSocket | No code path exists; stdio is structurally unreachable by a CONNECT proxy |
| **M4** | MCP methods other than `tools/call` | Not adjudicated anywhere |
| **H3** | eBPF exec observation | No ring-buffer reader is wired (`aa-runtime/src/runtime.rs:510-512`) — the events never leave the kernel |
| **N13** | eBPF TLS observation | Events are not bridged to the audit pipeline (`aa-runtime/src/runtime.rs:302-305,344-350`) |
| **H6** / **H7** | Browser and database governance | Not expressible in the policy AST at all — no `Browser`, no `Database` action kind |
| **H8** | Pre-execution mediation of a Claude Code `Bash` call | **No `PreToolUse` hook is ever registered.** The platform offers the mechanism; the product does not use it |
| **I4** / **I6** | Process-tree and proxy agent attribution | No agent id crosses fork/exec; the correlation bridge hardcodes `pid: 0`; the proxy stamps a constant `"aa-proxy"` |
| **G11** | Degraded-state visibility | Emitted, typed, and rendered nowhere |
| **S13** | The SDK honouring a deny | `resolve_decision` has no non-test caller in this repository |
| **C4** | Model response credential scanning | Absent on the LLM path |

## Question 4 answered *in the product's favour* — three corrections upward

Recording these matters as much as the negatives: an artifact that only ever
finds things worse than claimed is not being read carefully either.

| Row | Prior belief | Verified state today |
|---|---|---|
| **I1** | The agent Ed25519 seed is `SHA-256(public agent id)`, so anyone knowing the id can register as that agent | **Fixed (AAASM-5332).** The identity key is random CSPRNG, persisted owner-only with `O_EXCL`/`0600` and symlink/uid/mode validation, and registration requires a possession proof over a server-issued single-use nonce. The `SHA-256(agent_id)` derivation survives only as the *transport* key, where it is deliberately non-secret and the boundary is the socket's mode plus peercred |
| **L1** | `aasm run` registration has no REST contract — `POST /api/v1/agents` returns 405 — and `proxy_addr: null` launches unproxied, bypassing the possession proof | **Fixed.** Registration is gRPC `AgentLifecycleService.Register` with the Ed25519/`did:key` possession proof (`aa-cli/src/commands/run_registration.rs:1-35` documents the prior defect and its fix). `proxy_addr: None` on the live path is now reachable only via an explicit `--no-proxy`, which is itself refused where managed evidence exists, and ambient proxy env is stripped rather than inherited |
| **C2** | "Credentials are injected at execution time and never enter the model context" is a wholly unshipped claim | **Partly true, in a narrow form that does ship.** `AA_PROXY_PROVIDER_KEYS` populates a per-host store; on a MitM'd LLM host the proxy strips the agent's own `Authorization` / `x-api-key` and substitutes the operator's real key. The agent never needs to hold the provider credential. AAASM-5528 was right to remove the *unbounded* claim, but a bounded version is defensible — **provided all four conditions are named**: opt-in env var, MitM'd host only, proxy on the path, and `aasm run` still hands the child the whole parent environment (**C5**), which gives a shell tool everything the operator exported |

---

# Gap-to-ticket mapping

Every gap above resolves to exactly one of: an **existing** Jira issue, a
**new follow-up** this spike recommends, or an **accepted limitation**. Verified
against the live Epic children on 2026-08-06.

## Covered by an existing issue

| Gap | Rows | Issue | Status |
|---|---|---|---|
| eBPF unreachable in a released build — `aa-ebpf-loaderd` not shipped | H2 · H3 · H4 · N13 · P1 · P2 | [AAASM-5640](https://lightning-dust-mite.atlassian.net/browse/AAASM-5640) | To Do |
| Unreachable credential-injection surface (`DispatchTool`) | C3 | [AAASM-5631](https://lightning-dust-mite.atlassian.net/browse/AAASM-5631) | To Do |
| Proxy JSONL audit sink hardcoded to `None` | evidence pipeline | [AAASM-5641](https://lightning-dust-mite.atlassian.net/browse/AAASM-5641) | To Do |
| CONNECT tunnel emits an **allow** decision for payload it never inspects | N5 | [AAASM-5637](https://lightning-dust-mite.atlassian.net/browse/AAASM-5637) | To Do — re-verified still present at `aa-proxy/src/proxy/mod.rs:1325` |
| Dropped audit entries indistinguishable from tampering | G10 | [AAASM-5626](https://lightning-dust-mite.atlassian.net/browse/AAASM-5626) | To Do |
| Degraded-state reporting and protection attestation | G6 · G11 | [AAASM-5535](https://lightning-dust-mite.atlassian.net/browse/AAASM-5535) | **In Progress** |
| MCP transport mediation **and real agent identity binding** | M4–M9 · I6 | [AAASM-5533](https://lightning-dust-mite.atlassian.net/browse/AAASM-5533) | To Do |
| Host-wide mediation feasibility across platforms | H1 · P1–P4 | [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534) | To Do |
| Adversarial conformance harness (incl. a wire-level batch negative control) | M3 · every "Gap" evidence cell | [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532) | To Do |
| SDK quick-start enforcement-truth negative controls | S1–S9 | [AAASM-5529](https://lightning-dust-mite.atlassian.net/browse/AAASM-5529) | To Do |
| Machine-readable capability/evidence manifest | this artifact's YAML | [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) | To Do |
| Documentation CI gates for absolutes and stale evidence | all | [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536) | To Do |
| Stale crate-doc wiring claims (`aa-sandbox`, `aa-ebpf-common`) | H5 | [AAASM-5627](https://lightning-dust-mite.atlassian.net/browse/AAASM-5627) | To Do |
| `aa-ebpf` uprobe docstring claims `SSL_write_ex` is attached | N13 | [AAASM-5634](https://lightning-dust-mite.atlassian.net/browse/AAASM-5634) | To Do |
| CLI reason string claims the CA is never added to the macOS trust store | P3 | [AAASM-5639](https://lightning-dust-mite.atlassian.net/browse/AAASM-5639) | To Do |
| Absolutes in `examples` and the workspace-root agent instructions | — | [AAASM-5630](https://lightning-dust-mite.atlassian.net/browse/AAASM-5630) | To Do |
| Core doc migration to the canonical model | `docs/src/security/threat-model.md` and siblings | [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) · [AAASM-5606](https://lightning-dust-mite.atlassian.net/browse/AAASM-5606) | To Do |
| **Node default mode routes through an allow-all no-op client** | S7 | [AAASM-4991](https://lightning-dust-mite.atlassian.net/browse/AAASM-4991) | To Do — **filed as a docs-gap Bug; this survey shows it is an enforcement defect and it should be re-scoped and re-prioritised accordingly** |
| Kill-after-syscall race | H2 | [AAASM-3872](https://lightning-dust-mite.atlassian.net/browse/AAASM-3872) | To Do |
| MCP JSON-RPC batch bypass | M3 | [AAASM-4070](https://lightning-dust-mite.atlassian.net/browse/AAASM-4070) — fixed, but unit-only coverage and the nested-batch case is open | — |
| Proxy + eBPF backstop for direct-to-gateway bypass | I7 | [AAASM-3422](https://lightning-dust-mite.atlassian.net/browse/AAASM-3422) | To Do |
| Correlation bridge hardcodes `pid: 0` | I4 | `TODO(AAASM-150)` in `aa-runtime/src/correlation/mod.rs:47-49` | pre-existing |

## New follow-ups this spike recommends

Seven. Each is a defect or a decision this survey surfaced that no open issue covers.

| # | Recommendation | Rows | Why it is new | Suggested severity |
|---|---|---|---|---|
| **F1** | **`aa-devtool-codex` and `aa-devtool-windsurf` managed launches establish no CA trust** — they inject `HTTPS_PROXY` and nothing else, the exact configuration AAASM-5276 measured as failing the MitM handshake *silently*. Either inject the CA per launch as the Claude Code adapter does, or stop describing these as managed launches | L2 · L3 | The Claude Code fix was adapter-scoped; the same defect in two sibling adapters was never filed | **High** — a launch reported as managed may be inspecting nothing |
| **F2** | **A chunked or SSE upstream response on the MCP path is silently truncated to `Content-Length: 0`.** `handle_mcp_response_body` always calls `serialize_http_response(resp, &resp.body)` with an empty body; there is no transparent-relay fallback. The module doc at `aa-proxy/src/proxy/http.rs:13` asserts one exists — a comment contradicting its own code | M7 · N9 | Correctness bug plus a doc/code mismatch; not covered by 5533, which is about transports the proxy never sees | **High** — silent data loss for any streaming MCP server |
| **F3** | **No `PreToolUse` hook is ever registered for Claude Code.** `WRITABLE_KEYS` carries the boolean `allowManagedHooksOnly` but never a `hooks` array. This is the one platform-offered mechanism that could give pre-execution mediation of a `Bash` call — the H1 gap — for the flagship integration | H1 · H8 | 5534 asks whether host-wide mediation is feasible; this is a specific, available, unused mechanism that does not need a feasibility spike | **High** — closes the largest single coverage gap for one tool |
| **F4** | **Budget state that fails to load silently resets the cap to zero spend** (`aa-gateway/src/server.rs:155-163`), and eBPF policy that fails to parse silently yields an empty rule set (`aa-runtime/src/ebpf_control.rs:190-201`). Neither raises a `LayerDegradation`. Both are security-relevant fail-opens presented as warnings | G7 · G9 | 5535 covers *reporting* degradation; these two never report one | **Medium** |
| **F5** | **Tenant isolation is enforced at call sites, not at the storage layer.** `get_agent` by id carries no org predicate; `AgentFilter.org_id` applies only when the caller supplies it; `aa-storage-memory` has no `org_id` concept at all. Push scoping into the storage trait so a forgetful call site cannot leak across tenants | I5 | `e2e_org_isolation.rs` tests the paths that do scope; nothing prevents a new unscoped one | **Medium** |
| **F6** | **Decide how browser and database actions are modelled.** Neither is expressible in the policy AST. Either add action kinds, or state publicly that they are covered only insofar as they surface as `ToolCall` or `NetworkRequest` | H6 · H7 | A product-scope decision, not a bug | **Medium** — blocks an honest 5609 capability list |
| **F7** | **MCP adjudication is coupled to whole-machine MitM.** The only supported route to M1 forces `AA_PROXY_LLM_ONLY=false`, so an operator cannot adopt MCP governance without bringing every host under TLS interception. Either decouple them or document the coupling as a deliberate trade-off | M1 | Never stated publicly; 5609 cannot write "Choose Your Enforcement Path" without it | **Medium** |

## Accepted limitations

Recorded so they are not re-opened as defects.

| Limitation | Why accepted |
|---|---|
| The developer's own UID can remove the product from the path | Non-goal **N1**; ADR 0030 and ADR 0033 both state it |
| A fully privileged host administrator is out of scope | Non-goal **N2**; Epic AAASM-5526 states it |
| The SDK is advisory, not a security boundary | ADR 0002; correct by design. The claim wording must match, not the code |
| The audit chain is unkeyed and therefore tamper-evident, not signed | Non-goal **N8**; re-verified — `sha2` present and `hmac` absent across `aa-core/src`, and `aasm audit verify-chain` genuinely ships (`aa-gateway/src/audit.rs:142`; `aa-cli/src/commands/audit/mod.rs:14,31,44`) |
| The audit chain covers the JSONL sink only; the DB mirror drops `seq` / `previous_hash` / `entry_hash` | Deliberate and documented (`aa-gateway/src/storage/audit_bridge.rs:10-12`) |
| A secret split by a separator scans clean | AAASM-5368, accepted residual |
| macOS Endpoint Security / Network Extension | Non-goal **N6**, pinned by a test |
| No transparent network redirect | Non-goal **N9** |
| Opaque SaaS agents cap at `L1Observe` | Non-goal **N7**; the honest B7 answer |
| The eBPF syscall guard's load-time window and fork fail-open | Documented at `aa-runtime/src/ebpf_control.rs:114-121` and `aa-ebpf-probes/src/syscall_guard.rs:105`; a race-free fix needs a protocol change |

---

# Minimum defensible public guarantee today

This is the recommendation AAASM-5609 and AAASM-5588 should build from. It is
deliberately narrow, and every clause is carried by a row above.

> **Agent Assembly governs the actions it is on the path of.**
>
> For an agent that adopts a supported SDK and calls its initialiser, a policy
> `Deny` refuses a wrapped framework tool call before the tool body runs
> *(Python and Go today; Node requires `mode: "napi-inprocess"`)*.
>
> For a process launched through `aasm run` onto a trusted proxy, Agent Assembly
> refuses disallowed destinations at connection time, and scans and redacts
> recognised credentials in outbound requests to the hosts it inspects — three
> LLM providers by default, more if the operator configures them.
>
> For an MCP `tools/call` sent over HTTPS to one of those inspected hosts with a
> gateway configured, the control plane decides before the call is dialled, and an
> unenforceable framing is refused rather than forwarded.
>
> Every governed action produces a hash-chained audit record you can verify with
> `aasm audit verify-chain`.
>
> **Outside those paths Agent Assembly does not know what happened, and says so.**
> It does not mediate shell commands, subprocesses, file access, browser or
> database activity. It does not see raw TCP, UDP, QUIC, WebSocket, or MCP over
> stdio. It has no host-level interception on any platform in a released build. A
> tool started outside the managed path is not governed, and for most tools that
> is not detectable.

Three drafting rules for anyone deriving copy from this:

1. **Name the boundary class, not the word "universal".** Every guarantee above
   is B1, B2 or a conditional B3.
2. **Never let an absence of events imply an absence of activity.** An empty audit
   log is evidence about the observer.
3. **Do not promote a source-tree capability to a shipped one.** eBPF is the
   standing example: it is real, it is tested, and no released binary can load it.

---

# Go / Conditional Go / No-Go per boundary class

Acceptance criterion 7 requires a recommendation per boundary class.

| Class | Recommendation | Rationale |
|---|---|---|
| **B1 — one patched function** | **Go** | Python and Go SDKs deny before the body runs, fail closed, and are covered by tests that run on `main`. Publishable today with the initialiser requirement named |
| **B2 — one framework** | **Conditional Go** | Holds for Python's twelve adapters. Conditional on: (a) closing **S7** so the Node default enforces or fails loudly; (b) stating that LangGraph and Mastra are lineage-only; (c) documenting the two Python deny shapes |
| **B3 — one process** | **Conditional Go**, and only for *routed HTTP(S) egress* | The proxy genuinely refuses out of process and before dialling. Conditional on publishing the three-host `llm_only` default, the empty egress lists, the absence of ALPN, and the transports in N10–N12. **Never** state B3 for host actions — D2 has no mechanism |
| **B4 — one container** | **No-Go** | Nothing is container-aware. No mechanism enumerates or scopes to a container boundary. Do not claim it |
| **B5 — one host** | **No-Go** | E4 is the only element that could reach B5 and it is unreachable in every released build (AAASM-5640). Even in a source build it is observe-only except for one opt-in asynchronous kill. **This is the clearest No-Go in the matrix and the one most at risk of being claimed anyway** |
| **B6 — one managed device** | **Conditional Go, narrowly** | macOS root-owned managed settings is a real boundary a non-admin user cannot rewrite, and it is the only route to ADR 0030's `HostEnforced`. Conditional on: it is *tool-governance*, not data-path mediation, and whether the tool honours the keys is unmeasured (AAASM-5298's open half). Claim the file, never the enforcement |
| **B7 — opaque SaaS agents** | **No-Go** | `aa-devtool-saas` is hard-capped at `L1Observe`, is not registered in `SUPPORTED_TOOLS`, cannot launch, and cannot write settings. It is an audit-ingest adapter. Do not describe SaaS agents as governed |

---

# Cross-cutting findings (reported, not fixed)

This ticket owns `verification-reports/**` only. `docs/src/**` and
`docs/src/SUMMARY.md` are held by AAASM-5592, and the `aa-*` crates by
AAASM-5535. Everything below is therefore reported to its owner rather than
edited here.

## Code defects

| # | Finding | Location | Owner |
|---|---|---|---|
| 1 | Codex and Windsurf managed launches inject `HTTPS_PROXY` with no CA trust — the measured D-d silent-failure configuration | `aa-devtool-codex/src/lib.rs:281-303`; `aa-devtool-windsurf/src/lib.rs:295-315` | **F1 — new ticket** |
| 2 | Chunked/SSE upstream responses on the MCP path are re-serialised with `Content-Length: 0` | `aa-proxy/src/proxy/mod.rs` `handle_mcp_response_body`; `aa-proxy/src/proxy/http.rs:466-484,502-527` | **F2 — new ticket** |
| 3 | Budget state load failure silently resets the cap; eBPF policy parse failure silently yields an empty rule set. Neither raises a degradation | `aa-gateway/src/server.rs:155-163`; `aa-runtime/src/ebpf_control.rs:190-201` | **F4 — new ticket** |
| 4 | `get_agent` by id carries no org predicate; `aa-storage-memory` has no `org_id` concept | `aa-gateway/src/storage/postgres.rs:499-508`; `aa-storage-memory/src/**` | **F5 — new ticket** |
| 5 | CONNECT emits an **allow** decision for traffic then tunnelled uninspected — re-verified present | `aa-proxy/src/proxy/mod.rs:1325` | AAASM-5637 (open) |
| 6 | `aa-cli` and gateway lifecycle tests still mint registration keys via `derive_transport_key(agent_id)`, the derivation AAASM-5332 removed from production | `aa-cli/src/commands/run_registration.rs:583,668`; `aa-gateway/tests/lifecycle_service_test.rs:29,658,682,804,830,856` | AAASM-5535 or a test-hygiene follow-up |
| 7 | The correlation bridge hardcodes `pid: 0`, making pid-family correlation inert | `aa-runtime/src/correlation/mod.rs:47-49` | pre-existing `TODO(AAASM-150)` |

## Comments that contradict their own code

Each of these would mislead a reader who trusts the comment over the code. Two
are already ticketed; two are not.

| # | Comment | Code | Owner |
|---|---|---|---|
| 8 | `aa-proxy/src/proxy/http.rs:13` — *"the MCP path falls back to a transparent relay"* | It does not; `handle_mcp_response_body` always re-serialises | **F2** |
| 9 | `aa-sandbox/src/lib.rs:10-11` — *"consumed by `aa-proxy` via the `ToolRegistry` dispatch surface"* | `aa-proxy/Cargo.toml` has no `aa-sandbox` dependency (positive control: `aa-core` at `:17`) | AAASM-5627 |
| 10 | `aa-ebpf-common/README.md:11` — describes `aa-ebpf-programs` as the live BPF producer | It is a dead stub; `aa-ebpf/build.rs` builds only `aa-ebpf-probes` | AAASM-5627 |
| 11 | `aa-ebpf` uprobe docstring claims `SSL_write_ex` is attached | It never is | AAASM-5634 |

## Book pages still narrating the superseded model

Reported for AAASM-5592 / AAASM-5605; **not edited here**.

- `docs/src/security/threat-model.md` — routes readers to "the [three interception
  layers](three-layer-defense.md)" in its opening sentence (`:6`), and its threat
  scenario 3 asserts the fall-through framing ADR 0033's Alternatives explicitly
  rejects: *"eBPF SSL uprobes observe the plaintext if the agent bypasses both"*
  (`:57`). Scenario 2 states redaction happens *"on every path"* (`:53`), which
  D3 and D6 disprove. Its Assets table attributes network-egress protection to
  *"eBPF SSL uprobes"* (`:15`).
- The reconciliation this artifact recommends: `threat-model.md` should become the
  durable STRIDE catalogue keyed to the six elements, and cite this matrix for
  current-state coverage rather than restating it.

---

# Fields this artifact recommends for the AAASM-5531 manifest

The YAML source already carries the seventeen ticket-required fields. This survey
surfaced eight more that a manifest needs in order to be *checkable*, each because
its absence made a claim ambiguous somewhere above.

| Field | Values | Why the survey needs it |
|---|---|---|
| `default_state` | `on` \| `off` \| `open` \| `closed` | Question 3. Six capabilities ship as their default, not as themselves (N1, N4, M2, C1, C2, H2) |
| `reachable_in_release` | `true` \| `false` | Question 4. The single field that would have made AAASM-5640 impossible to miss. Should be derived from `scripts/check-release-completeness.sh`, not hand-written |
| `boundary_class` | `B1`…`B7` | Makes "universal" unwritable without a boundary, which is the Epic's security principle |
| `decision_timing` | `pre` \| `in-line` \| `post` \| `none` | Separates *Denied before execution* from the eBPF guard's post-hoc kill |
| `failure_posture` | `fail_closed` \| `fail_open` \| `fail_open_silent` | The third value is the finding: G7 and G9 fail open **without** emitting a degradation, which is materially different from G6 |
| `evidence_ref` + `evidence_runs_on_main` | test path + boolean | An evidence test that is path-gated off `main` (the whole eBPF suite) is weaker evidence than one in the standing suite, and today nothing records the difference |
| `deny_signal` | `raise` \| `sentinel_value` \| `none` | Six Python adapters return a `[BLOCKED …]` string and five raise; a caller catching only the exception treats a blocked call as a success |
| `redaction_actor` | `proxy_scanner` \| `gateway_instructions` | A gateway `Redact` verdict never replays the gateway's field paths; the proxy's own scanner does the work |

Two further recommendations for 5531, both learned here:

- **Derive `reachable_in_release` from the release script rather than restating
  it.** A manifest that hand-copies the binary list will drift exactly the way the
  eBPF claim did.
- **Make `coverage` a closed enum of ADR 0033 §6's eleven terms**, so a value
  outside the vocabulary fails validation. That is the machine-checkable half of
  AAASM-5536's V1 gate.

---

# Acceptance-criteria mapping

| Criterion | Where it is satisfied |
|---|---|
| Every currently supported SDK/framework/dev-tool/MCP path is represented | **D1** (12 Python adapters, 5 Node hook targets + 2 wrappers, Go), **D4** (10 MCP rows across every transport), **D5** (all 5 dev-tool adapters) |
| Direct and unmanaged paths are represented rather than omitted | **S10**, **S11**, **S12** (direct calls, unadapted frameworks, raw HTTP/subprocess/fs), **L6**, **L8** (unmanaged launch, `--no-proxy`), **N10**–**N12**, **M5**–**M8** |
| Observe-only, best-effort and pre-execution enforcement are not conflated | The `Mode` column carries enforce-vs-observe **and** sync-vs-best-effort separately, and `Coverage` is a closed ADR 0033 §6 term. H2 is recorded as **Detected**, never *Denied before execution*, precisely because the syscall completes first |
| Each advertised guarantee maps to at least one evidence row | Table 2 of every domain carries an `Evidence test / gap` cell. Where no test exists the cell says **Gap** rather than being left blank |
| Each known bypass maps to a mitigation, accepted limitation or follow-up | [Gap-to-ticket mapping](#gap-to-ticket-mapping) — 21 existing issues, 7 new follow-ups, 10 accepted limitations |
| The matrix is reviewed against source code, not README text alone | [Method](#method). Every row cites `file:line` with the symbol name; every absence carries a positive control; every path was checked with `git ls-files --error-unmatch`. Four comments that contradict their own code are recorded as findings |
| A final Go / Conditional Go / No-Go per boundary class | [Go / Conditional Go / No-Go](#go--conditional-go--no-go-per-boundary-class) — B1 Go · B2 Conditional · B3 Conditional · B4 No-Go · B5 No-Go · B6 Conditional · B7 No-Go |

## Deliverables

| # | Deliverable | Status |
|---|---|---|
| 1 | Machine-readable matrix source | [`AAASM-5527-capability-coverage-matrix.yaml`](AAASM-5527-capability-coverage-matrix.yaml), in `verification-reports/` for the path-ownership reason in ["Why this file lives here"](#why-this-file-lives-here). AAASM-5531 owns promoting it to a canonical, CI-validated location |
| 2 | Human-readable architecture and trust-boundary diagrams | **Deliberately not duplicated.** ADR 0033 §3 publishes the three views and is the canonical source; redrawing them here would create a second authority. [Trust boundaries](#trust-boundaries) T1–T6 is the tabular complement this artifact adds |
| 3 | Threat actors and attacker capability assumptions | [Threat actors](#threat-actors-and-capability-assumptions) A1–A4 |
| 4 | Bypass catalogue, demonstrated versus inferred | [Bypass catalogue](#bypass-catalogue) — 7 demonstrated, 6 groups inferred, plus what the product can detect |
| 5 | Gap-to-ticket mapping | [Gap-to-ticket mapping](#gap-to-ticket-mapping) |
| 6 | Minimum defensible public guarantee | [Minimum defensible public guarantee](#minimum-defensible-public-guarantee-today) |

## What this artifact does not claim

- **It is not exhaustive.** "No finding" is not "no bypass", and the absence of a
  row is not evidence that a path is covered.
- **It is a snapshot** of `remote/main` at `299de3883`. Line numbers rot; symbol
  names are given so drift is detectable. AAASM-5531 and AAASM-5536 exist to
  replace review-maintained tables with generated, gated ones.
- **It does not fix anything.** Every defect is reported to its owner above.
