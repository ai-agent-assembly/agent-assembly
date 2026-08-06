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
