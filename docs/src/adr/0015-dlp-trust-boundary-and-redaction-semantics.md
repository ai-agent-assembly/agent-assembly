# ADR 0015: DLP Trust Boundary, Redaction Fail-Safety & Heuristic Detection Limits

**Status**: Proposed
**Date**: 2026-07
**Ticket**: [AAASM-4945](https://lightning-dust-mite.atlassian.net/browse/AAASM-4945)

This ADR records the intended contract for the Data-Loss-Prevention (DLP) layer in
`aa-security` — the credential scanner and redaction primitives relied on by
`aa-runtime`, `aa-gateway`, and `aa-proxy` — and the adjacent graph-context
evaluation fail-safety in `aa-gateway`. It exists because the 20th security+QA
sweep (Epic [AAASM-4932](https://lightning-dust-mite.atlassian.net/browse/AAASM-4932))
surfaced a cluster of defense-in-depth findings ([AAASM-4936](https://lightning-dust-mite.atlassian.net/browse/AAASM-4936))
whose *correct* resolution depends on decisions that were never written down: what
the DLP layer promises, where it fails open vs closed, and how far the heuristic
detectors are meant to reach. One attempted fix (extending PEM redaction) silently
regressed a conformance golden vector precisely because the intended behavior was
implicit. This ADR makes the contract explicit so the deferred AAASM-4945 work — and
future detector changes — can be scoped and reviewed against a stated baseline. It
complements ADR 0004 (governance enforcement flow) and ADR 0002 (SDK security
boundary); it does not supersede them.

---

## Context

**What the DLP layer is.** `aa-security` owns a credential-detection scanner
(`CredentialScanner::scan`) and a redaction primitive (`ScanResult::redact`). It
detects secrets/PII in an action payload and rewrites them to opaque
`[REDACTED:<kind>]` labels before the payload is forwarded to an LLM, logged to the
audit trail, or copied upstream by the proxy. It is a **leaf crate** — no `aa-core`
dependency — consumed by every trusted enforcement layer.

**Two detector classes, deliberately different in authority.**

1. **Literal / structural detectors** — fixed prefixes and structural patterns
   (`AKIA…` AWS keys, `-----BEGIN … PRIVATE KEY-----` PEM headers, `xapp-`/`sk-`
   vendor tokens, Luhn-valid card numbers). These are **authoritative**: a match is
   a known secret shape, low false-positive, and is the primary contract.
2. **Generic entropy backstop** (`GenericHighEntropy`) — a whitespace token of
   length 20–64 with Shannon entropy > 4.5 bits/char, a contiguous hex run ≥ 64, or
   a base64 run ≥ 20 above the gate. This is **best-effort**: it catches unknown
   high-entropy blobs but is intrinsically bounded by entropy/length thresholds that
   an adversary who controls the payload can dodge.

**Threat model.** The adversary is a *steered or compromised agent* inside the trust
boundary that is trying to exfiltrate a secret past the redactor — by shaping the
payload so a detector misses it (encoding, spacing, dilution, truncation), or by
inducing a resolution error that makes an enforcement clause silently no-op. The DLP
layer is defense-in-depth: it is **not** the only control (network egress policy,
capability policy, and audit all sit alongside it), but it must not *silently* fail
in a way that converts a redaction miss into a plaintext leak.

**The forcing findings (AAASM-4936).** The sweep found: (L1) `redact()` emitted the
**raw** secret when a span fell off a UTF-8 boundary — a fail-**open**; (L2) several
heuristic evasions (entropy dilution, PEM short trailing line, card spacing, SSN
adjacent digit); (L5) graph-context variables that fail **open** (an unresolvable
variable makes a `deny` clause not deny). L1/L3/L4 shipped; the L2 PEM attempt
**regressed** the `EcPrivateKey` conformance vector by letting an extended literal
span coexist with an overlapping `GenericHighEntropy` span instead of subsuming it,
and was reverted. That regression is the direct evidence that the overlap/precedence
rules and the fail-safety intent must be stated before more detectors are touched.

---

## Decision

### 1. Redaction fails **closed**, always

`ScanResult::redact` MUST NOT, under any input, emit a byte of a detected secret in
the clear. When a finding's span cannot be applied faithfully (out-of-range offset,
non-UTF-8-boundary, caller text ≠ scanned text), redaction degrades to an opaque
whole-value `[REDACTED]` rather than passing the original through. (Shipped in
AAASM-4936; this ADR ratifies it as the standing contract.) A detected secret whose
span is untrustworthy is treated as *more* dangerous, not less.

### 2. Literal detectors are authoritative and **subsume** overlapping heuristic spans

When a literal/structural finding (e.g. `EcPrivateKey`) overlaps a
`GenericHighEntropy` finding, the specific finding MUST win and its span MUST cover
the whole logical secret as a **single** `[REDACTED:<specific>]` label. Overlap
resolution is by finding precedence (`GenericHighEntropy` = lowest), and an extended
literal span MUST **merge/replace** overlapping lower-precedence spans, never coexist
with them. This is the invariant the reverted PEM change violated; any future PEM
"full-block" extension MUST re-establish it and keep the existing conformance vectors
byte-identical.

### 3. Heuristic detection has a **stated, bounded** scope — and that boundary is intentional

The entropy backstop is best-effort by design. Its thresholds (20–64 token window,
> 4.5 bits/char, ≥ 64 hex, ≥ 20 base64) are a deliberate trade-off against
false-positives on ordinary text/identifiers. We do **not** promise to catch every
adversarially-shaped secret via entropy alone. Coverage of a *known* secret shape is
the job of a **literal detector**, which is precise and testable. Tightening the
entropy heuristic to chase an evasion is only acceptable when it does not raise the
false-positive rate on the conformance corpus (see Validation).

### 4. Graph-context evaluation: distinguish *legitimate absence* from *resolution failure*, deterministically

Today every `PolicyContext` getter returns `Option<T>` and a `None` short-circuits
the referencing clause to `false` (`deny` doesn't deny, `requires_approval_if`
doesn't fire) — *null-as-no-match*, documented and snapshot-tested. This is **correct
when absence is legitimate** (a team-less agent has no `team_active_agents`, so a
team-scoped deny rightly does not apply to it). It is a **fail-open when the `None` is
caused by a resolution error** (registry unavailable, lookup/backend failure),
because a deny rule then silently stops denying.

**Decision.** The context layer MUST distinguish the two causes — `None`
(legitimately absent) vs an explicit *resolution failure* — rather than collapsing
both into a bare `None`. This requires the trait to carry the distinction (e.g.
`Result<Option<T>, ContextError>`, or a dedicated "unavailable" signal), not
`Option<T>` alone. Given the two causes, evaluation is **deterministic** per the
following table; there is no configurable or per-call variability:

| Clause | Value resolves `Some(_)` | **Legitimate absence** (`None`, valid) | **Resolution failure** |
|---|---|---|---|
| `deny` (conditional) | denies iff expression `true` | *no-match* — does **not** deny | **DENY** (fail-closed) |
| `requires_approval_if` | fires iff expression `true` | *no-match* — does **not** fire | **REQUIRE APPROVAL** (fail-closed) |
| `allow` (conditional) | grants iff expression `true` | *no-match* — condition does not grant | *no-match* — **MUST NEVER grant** on failure |

Rules, stated so an implementer cannot guess wrong:

1. **`deny` + resolution failure ⇒ deny.** A deny rule whose variable cannot be
   resolved denies the action.
2. **`requires_approval_if` + resolution failure ⇒ require approval.** The action is
   escalated, not silently allowed.
3. **`allow` + resolution failure ⇒ no match, and MUST NEVER grant access.** A
   conditional allow whose variable cannot be resolved does not satisfy its condition;
   failure can never be laundered into a grant. (Unconditional `allow` — one that
   references no graph variable — is unaffected; there is nothing to resolve.)
4. **Legitimate absence remains `null-as-no-match`** for every clause type, unchanged
   from today's documented behavior.
5. **Every resolution failure MUST be audit-visible.** The evaluation emits an audit
   record identifying the unresolved variable, the clause it affected, and the
   fail-safe action taken (deny / approval / no-grant), so a silently-degraded
   decision is never invisible to an operator.

Because this changes a documented, snapshot-tested invariant, it ships **only** after
this ADR is Accepted, as its own PR (workstream §5.3) with fixtures covering all five
paths — absence, failure, `deny`, `requires_approval_if`, and `allow` — plus the
audit-evidence assertion.

### 5. Scope split for implementation (post-acceptance)

AAASM-4945 is split into three narrowly-scoped, separately-reviewable changes, each
with focused regression **and** conformance tests:

1. **Safe, behavior-preserving hardening** — completeness fixes that do not change
   any existing golden vector (e.g. a correct PEM full-block *span-merge* per §2,
   with the existing `EcPrivateKey` vector unchanged and a new short-trailing-line
   vector added).
2. **Heuristic changes** — any threshold/detector tightening (entropy dilution, card
   spacing, SSN adjacent-digit), each gated on a documented false-positive analysis.
3. **Graph-context resolution-failure semantics** — distinguish legitimate absence
   from lookup/resolution failure and implement the deterministic §4 table
   (deny⇒deny, approval⇒approve, allow⇒never-grant), with audit evidence on every
   failure. Migrate the `PolicyContext` implementations carefully (production wiring
   + the test fakes), and add fixtures for all five paths — absence, failure, `deny`,
   `requires_approval_if`, `allow`. Delivered as its own PR.

Scope guard: workstream §5.2 (heuristics) MUST NOT lower entropy thresholds or widen
the token window — entropy dilution is an accepted residual risk (see Accepted
risks). Card-spacing and SSN-boundary tightening are **out of the initial split** and
may be picked up later as separate, false-positive-tested hardening tasks.

---

## Accepted risks

- **Entropy-backstop false negatives remain.** An adversary who dilutes entropy below
  the gate, or splits a secret across the token window, can evade the *generic*
  detector. Accepted because (a) known shapes are covered by literal detectors, (b)
  DLP is one control among several (egress + capability + audit), and (c) lowering
  the gate to catch these would false-positive on ordinary identifiers and high-
  entropy-but-benign data. Mitigation is *adding a literal detector* for any newly
  important shape, not loosening the heuristic.
- **PEM short-trailing-line residual** until hardening §5.1 ships: an unusual PEM
  whose final base64 line is too short/low-entropy for the entropy pass may leave
  that line unredacted. The common PEM case is fully covered by the literal header
  detector (proven by the conformance vector). Tracked as the edge the reverted
  change tried, and mis-implemented, to close.
- **Card/SSN spacing variants** below the current thresholds may evade until §5.2.
  Accepted as best-effort PII coverage; the authoritative path for regulated PII is
  policy + audit, not the heuristic alone.

## Explicitly forbidden designs

- **Do not** let `redact()` emit any original secret byte on a span/boundary/mismatch
  error. No "best-effort partial redaction" that passes unmatched remainder through.
- **Do not** extend a literal-detector span in a way that leaves an overlapping
  `GenericHighEntropy` span (or an `-----END-----` marker, or any block remainder)
  separately labeled or in the clear. One secret → one subsuming label.
- **Do not** lower the entropy gate or widen the token window to chase a single
  evasion vector; add a precise literal detector instead.
- **Do not** collapse "variable legitimately absent" and "variable failed to resolve"
  into the same silently-allowing `None` for `deny` / approval clauses.
- **Do not** let a conditional `allow` grant access on a resolution failure, and
  **do not** let any resolution failure degrade a decision *silently* — every failure
  must emit audit evidence.
- **Do not** change any committed conformance golden vector to make a detector change
  pass; a changed vector must be justified as a *better* redaction, reviewed on its
  own.

## Consequences

- **Operators / SaaS:** redaction behavior is unchanged for the common case; the
  graph-context change (§4) means a policy whose `deny`/approval clause references a
  variable that *fails to resolve* will now deny/escalate (and a conditional `allow`
  will not grant) instead of silently allowing — a stricter, safer default. Every such
  failure is now **audit-visible**, so operators can see when a decision was made on
  degraded context (and fix the underlying resolution outage). Legitimate absence is
  unchanged, so existing well-formed policies see no behavioral difference.
- **SDK/CLI:** no surface change; the DLP layer is internal to the trusted core.
- **Future contributors:** any detector or context change is now measured against a
  written contract (fail-closed redaction, literal-subsumes-heuristic, bounded
  heuristics, absence-vs-failure) and the conformance corpus — no more implicit
  intent.

## Operational guidance

- Treat the entropy backstop as best-effort in threat modeling; rely on literal
  detectors + egress/capability policy + audit for anything that must not leak.
- When a new secret shape becomes important, request a **literal detector** (precise,
  testable) rather than asking for the entropy gate to be loosened.

## Validation requirements

- The `conformance` credential-detection corpus (`conformance/tests/credential_detection.rs`,
  `all_vectors_redact_correctly`) MUST stay green on every DLP change; existing
  vectors byte-identical unless a change is explicitly justified as a better redaction.
- Each §5 sub-change ships with: a **regression** test proving the specific gap is
  closed, and, where it touches detection output, a **conformance** vector.
- Heuristic changes (§5.2) MUST include a false-positive check against the benign
  corpus (ordinary identifiers/text) demonstrating no new FPs.
- The graph-context change (§5.3) MUST add fixtures covering all five paths in
  `tests/graph_vars_fixture_test.rs` — legitimate-absence (unchanged no-match) and
  resolution-failure against each of `deny` (⇒ deny), `requires_approval_if` (⇒
  approval), and conditional `allow` (⇒ no-grant) — **plus** an assertion that each
  resolution failure emits the expected audit record.

## Reconsideration triggers

- A discovered redaction *bypass* that leaks plaintext (not merely a heuristic FN) —
  re-open immediately.
- A regulated-PII or compliance requirement that makes best-effort heuristic coverage
  insufficient (would motivate authoritative detectors or an upstream classifier).
- A new deployment edition (e.g. an enterprise DLP mode) with a different adversary
  or a stricter fail-safety requirement.
- Introduction of a context variable whose *absence* is security-relevant in a way §4
  does not cover.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-4945](https://lightning-dust-mite.atlassian.net/browse/AAASM-4945) | The ticket this ADR unblocks; implementation split per §5 |
| [AAASM-4936](https://lightning-dust-mite.atlassian.net/browse/AAASM-4936) | Sweep finding cluster; L1/L3/L4 shipped, L2/L5 deferred here |
| [AAASM-4932](https://lightning-dust-mite.atlassian.net/browse/AAASM-4932) | 20th security+QA sweep Epic (closed) |
| [ADR 0004](0004-governance-enforcement-flow.md) | Complements — enforcement flow the DLP layer sits inside |
| [ADR 0002](0002-sdk-security-boundary.md) | Complements — trust-boundary framing |
| Implementation PRs | _pending ADR acceptance (§5.1 / §5.2 / §5.3)_ |
