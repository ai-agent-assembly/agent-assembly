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
