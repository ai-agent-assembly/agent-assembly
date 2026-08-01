# ADR 0032: Local-First Sensitive-Data Provider Architecture

**Status**: Accepted
**Date**: 2026-08
**Ticket**: [AAASM-5269](https://lightning-dust-mite.atlassian.net/browse/AAASM-5269) (Spike), [AAASM-5343](https://lightning-dust-mite.atlassian.net/browse/AAASM-5343) (acceptance)

This ADR records how Agent Assembly detects sensitive data: a deterministic
in-process fast path that stays authoritative for every synchronous decision, a
canonical provider-neutral finding model, and — **deferred post-v1 by decision
D-1** — optional local-only providers consulted asynchronously for large or
high-risk payloads. It **complements**
[ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md), whose trust
boundary and fail-safety rules it preserves unchanged and whose reconsideration
trigger #2 ("an upstream classifier") invited it; it **defers to**
[ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) on the
verdict vocabulary and to
[ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) on the form
a local boundary may take. It supersedes nothing.

Supporting evidence, measurements and the full current-state survey are in
[the AAASM-5269 Spike report](../research/AAASM-5269-sensitive-data-provider-architecture.md).

> **Both open decisions were resolved on 2026-08-01** by the product owner
> (Bryant Liu), recorded in AAASM-5343, and a third decision (D-3, the release
> target for the `zh-TW` defect) is recorded alongside them. D-1: out-of-process
> providers are **not in scope for v1**. D-2: `RuntimeVerdict` stays frozen and
> an additive `sensitive_data_disposition` field carries the finer vocabulary.
> See §10.
>
> **Sections 4 through 7 therefore describe deferred post-v1 specification**, not
> v1 commitments — they are retained rather than deleted so the follow-up ADR
> inherits the analysis instead of repeating it. Parts of the Accepted risks,
> Consequences, Operational guidance and Validation requirements sections are
> likewise scoped to that deferred work and are marked where they are.

---

## Context

Detection today is a single Aho-Corasick-based scanner in `aa-security`
(`scanner.rs`), consulted synchronously by the gateway and the proxy. It has 28
`CredentialKind` variants — 27 of them built-in detectors enumerated by
`CredentialKind::ALL` — three PII detectors (credit card, email, US SSN), and
no locale dimension at all. The Epic asks whether external engines should be
allowed to contribute findings, and under what boundary.

Four facts from the survey shape the answer, and each is a measurement rather
than a preference.

**The fast path is genuinely fast, and the transport tax is not.** The built-in
scanner costs 5.8 µs p50 on a 449-byte tool call. Moving that same payload to an
out-of-process provider that performs *no detection at all* costs 43.8 µs over
loopback TCP — over 7× the entire current scan — 9.1 µs over a Unix domain
socket, and 61.6 µs if the connection is not reused. At 32 KB the same TCP tax
is 10%, and at 1 MB it is 4%. Out-of-process
inspection is uneconomical exactly where the synchronous enforcement path lives,
and cheap exactly where deep inspection is wanted.

**External engines are disqualified from the synchronous path by margin, not by
a close call.** Presidio Analyzer costs 12.28 ms p50 on a 592-byte call — ~2 000×
the Rust path — 613 ms at 32 KB, and returns HTTP 500 for payloads at or above
~524 KB. Its idle resident memory is 746 MiB against a 6.8 MB `aa-runtime` image.

**Local-only operation is achievable and was verified, not assumed.** On a
`docker network create --internal` network Presidio reached `healthy` in 5.4 s,
served real requests, and could not reach the public internet. Models are baked
into the published image.

**The current heuristic layer is mis-calibrated for non-English input.** 32 KB of
ordinary mixed `zh-TW`/English agent traffic containing zero secrets produces 87
`GenericHighEntropy` findings; the byte-equivalent English produces none. Under
`credential_action: Block` an agent communicating in Chinese is denied outright.
This is a defect in existing code, fixed ahead of and independently of this
architecture, but it constrains the design: any locale pack is built on top of a
tokenisation and entropy model that must first be made script-aware.

### Threat model

The adversary set differs by deployment and must not be collapsed:

- **A malicious or compromised provider** *(not a v1 adversary — D-1)*. It sees
  payload content by construction, so the mitigations are containment (no egress)
  and non-authority (its output is evidence, never a decision). It may also
  return crafted spans — and **that half is a v1 concern regardless**, because
  any detection source can produce a bad span: redaction must remain fail-closed.
- **A local unprivileged user** *(not a v1 adversary — D-1; there is no local
  socket in v1)*. On a developer host, any local user can reach a `127.0.0.1`
  socket, and the kernel supplies no peer identity over loopback TCP — the
  reasoning ADR 0030 forbidden design #7 already recorded.
- **A supply-chain adversary** *(not a v1 adversary for provider artifacts —
  D-1)*. Mutable image tags, unsigned artifacts and runtime model downloads are
  the delivery vectors.
- **An agent attempting evasion.** Encoding, splitting and script-mixing are all
  live techniques; the zh-TW finding shows script-mixing already changes detector
  behavior today.

Providers are **sensors**. Agent Assembly remains the sole policy authority, as
ADR 0002 and ADR 0015 already require.

---

## Decision

### 1. The deterministic Rust scanner is the fast path, and it is always available

Every synchronous, pre-action decision is made from in-process deterministic
detection alone. No provider may be consulted on a synchronous enforcement path.
The scanner remains a leaf crate with no heavy dependency, so it continues to run
in the SDK layer and in WASM, where no external engine can run at all.

### 2. Findings become a canonical, provider-neutral model

A canonical finding type owns category, severity, confidence band, byte span,
detection method, provenance and status. Provider-native schemas are mapped at
the adapter boundary and never leak into policy, audit, API or dashboard
contracts.

The existing `CredentialKind` variants and their `as_str()` redaction labels are
**frozen**. They are pinned by 26 conformance vectors and exposed publicly by
`GET /api/v1/scrub/patterns`. The canonical model maps 1:1 onto them; it does not
replace them.

Locale-specific entities are expressed as **locale-qualified categories**
(`NATIONAL_ID[zh-TW/arc_new]`), not as new `CredentialKind` variants, so policies
need no per-locale rewrite and `CredentialKind::ALL` stays stable.

### 3. Detection is split into a fast path and a deep path

| | Fast path | Deep path |
|---|---|---|
| When | every inspected action | large payloads, high-risk destinations, escalation |
| Where | in-process | **in-process only in v1** (D-1); out-of-process deferred post-v1 |
| Timing | synchronous, pre-action | asynchronous |
| Authority | decides | advises; may trigger follow-up action |
| Budget | must not regress today's cost | bounded, cancellable |

Escalation is by risk class and payload size, never by default.

### 4. Providers are sensors with a declared capability set

> **Deferred post-v1 (D-1).** No provider exists in v1, so nothing here is a v1
> requirement. Two rules in this section are **not** deferred, because they are
> general sensor-fusion invariants that bind the canonical finding model itself:
> an unsupported locale or exceeded ceiling is a **capability miss, never a clean
> scan**, and no detection source may return raw secret material.

A provider declares the categories, locales, payload-size ceiling and confidence
semantics it supports. Routing consults only providers whose declared
capabilities cover the request.

**An unsupported locale or an exceeded ceiling is a capability miss, never a
clean scan.** This is not a stylistic rule: Presidio returns HTTP 200 with zero
findings for Chinese text submitted as `en`, so an adapter that falls back on
locale would silently report "no sensitive data" for every Chinese payload.

**A provider must never return raw secret material.** Gitleaks populates
`Finding.Secret` with the actual secret unless `--redact=100` is set; the adapter
must set it and must reject any response carrying raw match text.

### 5. Provider failure semantics are explicit and never silently clean

> **Deferred post-v1 (D-1).** No provider exists in v1. The invariant that a
> detection failure **never downgrades to "clean"** is *not* deferred — it binds
> any detection path, including the in-process one.

Timeout, error, unavailability, capability miss and fallback are distinct
outcomes, each recorded. A deep-path failure never downgrades to "clean"; it
records the failure and leaves the fast-path decision standing. Because the
provider is off the synchronous path by §3, a deep-path failure cannot block an
action.

Note that Presidio returns an unhandled HTML 500 for oversized payloads *below*
its documented limit, so an adapter cannot distinguish "too large" from "crashed"
by status code; both map to `provider_error`, not to a clean result.

### 6. Local-only, egress-denied, and never a silent host modification

> **Deferred post-v1 (D-1).** No out-of-process provider exists in v1, so this
> section binds nothing that v1 ships. It is retained as the specification a
> future provider ADR starts from. Three rules in it are *not* deferred and hold
> unconditionally: the raw-content rule and the no-third-party-SaaS rule in the
> first paragraph, and the **no-silent-host-modification** rule in the second
> ("never installs Docker, obtains root, or runs `pip install`"), which forbidden
> design #13 restates unconditionally.

Providers run locally or on an operator-controlled private network. Raw content
never goes to a third-party SaaS service. Provider workloads are egress
deny-by-default.

Agent Assembly **owns** manifest schema and validation, capability discovery,
digest and signature verification, readiness/liveness, smoke tests and resource
reporting. It **generates and validates** deployment assets and egress policy. It
**never** installs Docker, obtains root, or runs `pip install` on the host.
Container lifecycle is the operator's; Agent Assembly validates and reports.

Where a local transport is needed it is a **Unix domain socket with
peer-credential checks**, not loopback TCP — following the reasoning of ADR 0030
forbidden design #7, and independently supported by the measurement that UDS is
roughly 4–5× faster than loopback TCP for small payloads.

### 7. Deployment placement is chosen by resident memory and latency need

> **Deferred post-v1 (D-1).** v1 has nothing to place. Retained as analysis for
> the follow-up ADR.

Use a **same-Pod sidecar** only when the provider's resident memory multiplied by
the replica count is acceptable *and* per-request latency is genuinely critical.
Otherwise use a **cluster-local shared service**. Presidio at 746 MiB fails the
first test and, being ineligible for the synchronous path, does not need the
second — Presidio is shared-service-only.

**Provider** Docker Compose examples are in scope for the deferred work — this
sentence scopes provider assets only and does not narrow the workspace-wide
policy that Compose examples are permitted. Kubernetes production orchestration
remains a research question under
[ADR 0006](0006-limited-self-host-k8s-terraform.md), not committed
implementation work.

### 8. Sensitive-data decisions get their own event and projection

A versioned `SensitiveDataDecisionEvent` records identity and lineage, the
attempted action and its destination, policy attribution, finding counts by
category, detection provenance, enforcement outcome, and whether execution
occurred. Findings are normalized child rows.

This projection is written **alongside** the existing
`audit_entry_to_storage_event` bridge, which is left untouched. That bridge loses
14 fields including every credential finding, the hash chain and all lineage
except `team_id`, and its target table currently has no reader at all; it is
superseded by attrition rather than extended field by field.

**Event counts and finding counts are distinct metrics** and may never be
collapsed. An action containing three findings that is blocked increments
`blocked_event_count` by 1 and `blocked_finding_count` by 3.

**"Prevented" requires proof.** An event may be counted as prevented transmission
only when the enforcement point is pre-transmission, the decision was deny or a
transforming disposition, explicit execution evidence records that the action did
not reach its destination, and the action was not in observe mode. The observable
already exists — `ForwardedPayload::NotForwarded` — but only on one of the two
`dial_upstream_tls` call sites, so today it is produced solely on the
protection-probe branch and is never persisted. Generalising it to every
pre-transmission decision and persisting it is what this requires. Everything
else is *detected*.

Note that redaction **forwards** scrubbed bytes upstream, so a redacted action is
a transformed transmission and not a prevented one.

### 9. Raw sensitive values never leave the tamper-evident tier

Raw values never enter logs, metric labels, traces, dashboard payloads or API
responses. Offsets and lengths are permitted **only** in the tamper-evident audit
tier, because a length plus a category can identify a value in a small domain.
Field *paths* are safe and are the drill-down granularity.

Metric labels are restricted to the bounded set `{category, severity,
confidence_band, outcome, detection_method, provider_id}`.

**Tenant-keyed HMAC fingerprints are permitted only above ~80 bits of value
entropy.** A Taiwan national ID has ≈5.2 × 10⁸ candidates and enumerates in under
a second on one GPU given the tenant key, so fingerprinting is unavailable for
every PII category and admits only long random secrets.

### 10. Resolved product decisions

Both decisions this ADR opened were answered by the product owner (Bryant Liu)
on **2026-08-01**, recorded in AAASM-5343. A third decision, D-3, was made at the
same time and is recorded below.

#### D-1 — out-of-process providers are NOT in scope for v1

v1 detection is **entirely in-process**. Presidio, Gitleaks, provider
containers, a provider manager, same-Pod provider sidecars, cluster-local
provider deployments and any out-of-process provider transport are excluded from
this implementation cycle.

Consequences that bind implementation:

- **§4 (provider capability model), §5 (provider failure semantics), §6
  (transport, lifecycle, egress) and §7 (deployment placement) are deferred
  post-v1 specification.** They are retained, not deleted, so a future ADR
  inherits the analysis and the measurements rather than re-deriving them. No v1
  ticket may cite them as a requirement — except the invariants their section
  markers explicitly carve out, which bind any detection source and therefore
  bind v1.
- The **provider port and its in-tree test double remain in v1** — not as a new
  permission this ADR grants itself, but because they are Phase 2 of the
  migration in the [Spike report §8](../research/AAASM-5269-sensitive-data-provider-architecture.md),
  and the option the product owner adopted is that report's option A,
  "in-process, in-tree adapters only (v1)". The v1 line falls between Phase 3 and
  Phase 4. The constraint is on *what the port may route to*, not on where the
  port sits: the port **may** wrap the in-process deterministic scanner on the
  synchronous path — that is exactly what `B-8` formalises at
  `aa-gateway/src/engine/mod.rs:1443`, which is inside the synchronous
  `EngineInner::evaluate` — but **no out-of-process or third-party provider
  implementation may be reachable from a synchronous enforcement path**
  (forbidden design #1), and **no adapter that leaves the process may ship**.
- The v1 threat model **shrinks**: provider compromise, provider egress and
  provider supply-chain are not v1 threats, since no provider exists. The
  corresponding entries in §5.5 of the Spike report remain valid for the deferred
  work only.
- The forbidden designs in this ADR remain in force regardless — in particular
  #1 (no provider on a synchronous path) and #7/#8, which constrain the deferred
  design if and when it is taken up.

The evidence that made this the low-cost answer: Phases 0–3 of the
[Spike report's §8 migration](../research/AAASM-5269-sensitive-data-provider-architecture.md)
contain no *out-of-process* provider and still deliver the locale correctness
fix, the canonical model and the entire event/analytics layer without touching
any accepted ADR.

#### D-2 — `RuntimeVerdict` stays frozen; disposition is a separate additive field

ADR 0018's five-way `RuntimeVerdict` (`Allow` / `Narrow` / `Scrub` / `Pending` /
`Deny`) is **not** extended, renamed or reordered. ADR 0024 establishes that
adding an enum variant is not additive on the wire, so extending it would be a
breaking change to a deliberately frozen contract.

The finer vocabulary lives in a **new, additive, optional** field —
conceptually `sensitive_data_disposition` — carrying:

`redact` · `mask` · `tokenize` · `require_approval` · `approval_granted` ·
`approval_denied` · `shadow_only` · `none`

Binding rules for its implementation:

- It is **additive and optional**. Absent or `none` must mean exactly what
  today's absence of the field means, so every existing consumer keeps working
  unchanged.
- Every disposition other than `none` maps onto an existing `RuntimeVerdict`, so a reader that
  understands only `RuntimeVerdict` still reaches a correct, if coarser,
  conclusion. The mapping is part of the contract and is not left to the
  implementer:

  | `sensitive_data_disposition` | `RuntimeVerdict` |
  |---|---|
  | `redact` / `mask` / `tokenize` | `Scrub` |
  | `require_approval` | `Pending` |
  | `approval_granted` | `Allow` |
  | `approval_denied` | `Deny` |
  | `shadow_only` | `Allow` |
  | `none` | unchanged — the verdict carries the whole meaning |

- The Rust and wire representations must be designed together and must satisfy
  ADR 0018 and ADR 0024. Public API and wire compatibility are preserved; any
  breaking representation requires a separately approved ticket.
- The field records **what happened to the payload and to the approval of the
  action**, at a granularity `RuntimeVerdict` deliberately does not carry. It is
  not a second authorisation channel: nothing may consult it to decide whether an
  action is permitted, and `RuntimeVerdict` remains the authoritative outcome.

#### D-3 — the fix for the `zh-TW` false-positive defect ships in `v0.0.1-rc.7`

Recorded here for traceability; the fix is carried by
[AAASM-5344](https://lightning-dust-mite.atlassian.net/browse/AAASM-5344) rather
than by this ADR. It is treated as an urgent production defect **ahead of** the
architecture migration, because under `credential_action: Block` an agent
communicating in Chinese is denied outright today.

Two constraints on that fix, stated as the product owner gave them:

- it must ship with **CJK/script-aware conformance coverage**, since the absence
  of any CJK vector is precisely why the defect survived;
- it must **not weaken detection of ASCII base64, hex or high-entropy secrets**.

Note the third term: the detector being modified *is* the high-entropy one, so
"do not weaken high-entropy detection" is the constraint that actually binds this
fix, not a formality. In particular a naive "skip any token containing
non-ASCII" implementation would create a script-prefix bypass — prepend one CJK
character to a secret and the whole token is skipped. AAASM-5344 therefore
requires an explicit bypass test.

The supporting constraints already in this ADR are §2 (the `CredentialKind`
variants and labels are frozen and pinned by 26 conformance vectors), forbidden
design #9 (never edit a committed golden vector to make a change pass) and
validation requirements 1–2.

---

## Accepted risks

- **Deterministic detection has a coverage ceiling.** Without NER we will not
  detect unstructured PII such as personal names in free text. Accepted because
  ADR 0015 already records that detection is heuristic and not a guarantee, and
  because the alternative costs 2 000× on the synchronous path.
- **Locale recognizers carry irreducible false positives.** ~22% of random
  8-digit strings pass the 統一編號 checksum and ~10% pass the national-ID
  checksum; phone and passport formats have no checksum at all. Context keywords
  reduce but do not eliminate this. We state the residual rather than claim
  precision.
- **A provider sees payload content** *(not a v1 risk — D-1; no provider
  exists)*. Containment (no egress) and non-authority bound the damage; they do
  not eliminate the exposure. Accepted only for operator-deployed local
  providers.
- **Deep-path findings arrive after the action** *(not a v1 risk — D-1; there is
  no deep path)*. By construction, asynchronous inspection cannot prevent the
  transmission it inspects. Its value is detection,
  alerting and subsequent policy adjustment — and the metric dictionary must not
  let those be counted as prevention.
- **Writing a second projection duplicates storage.** Accepted for the duration
  of the migration in exchange for not mutating a hash-chained audit path.

---

## Explicitly forbidden designs

1. **Any provider on a synchronous, pre-action enforcement path.** Measured at
   ~2 000× the fast path for the dominant payload class.
2. **Treating a capability miss, a timeout, or a provider error as a clean
   scan.** Presidio's silent-clean response for unsupported locales makes this a
   live hazard, not a hypothetical one.
3. **Bundling Python, NLP models or any provider into the core image.**
4. **Sending raw content to a third-party SaaS classification or DLP service**,
   under any configuration.
5. **Letting a provider's native taxonomy, confidence scale or span convention
   reach policy, audit, API or dashboard contracts.** Presidio labels a Taiwanese
   mobile number `DATE_TIME(0.85)` above `PHONE_NUMBER(0.40)`; a "top-scoring
   entity wins" adapter is forbidden.
6. **A provider adapter that can return raw secret material.** Gitleaks without
   `--redact=100` is the concrete case.
7. **Loopback TCP for a local provider transport.** Reachable by every local
   user, with no kernel-supplied peer identity (ADR 0030 #7).
8. **Dynamic shared-library loading or `inventory`-style implicit registration of
   adapters inside a trusted process** (ADR 0030 #8, restated here because it is
   the tempting shortcut for a "plugin" architecture).
9. **Editing a committed golden conformance vector to make a detector change
   pass** (ADR 0015).
10. **Redefining or renaming `CredentialKind` variants or their `as_str()`
    labels**, which are pinned by conformance vectors and published by
    `/api/v1/scrub/patterns`.
11. **Collapsing event counts and finding counts**, or calling an outcome
    "prevented" without execution evidence.
12. **Raw values, offsets, lengths or fingerprints in metric labels, traces, or
    API responses.**
13. **Silently installing Docker, acquiring root, or running `pip install` on the
    host.**
14. **HMAC fingerprinting of low-entropy PII.** Enumerable in under a second.
15. **Extending `audit_entry_to_storage_event` field-by-field** instead of
    writing a dedicated projection beside it.

---

## Consequences

**Operators** gain sensitive-data analytics that distinguish blocked from
redacted and events from findings, and a truthful prevention metric. In v1 they
take on **no** provider lifecycle, because there is no provider; if the deferred
deep path is later accepted, they would — Agent Assembly generates and validates
the assets but does not run the container runtime.

**SaaS** gains a bounded-cardinality metric surface and a tenant-scoped event
store. Deep-path providers are a per-tenant cost decision, not a platform default.

**SDK / CLI consumers** see no change. `CredentialKind` and the redaction labels
are frozen, so no vector, SDK or generated client moves.

**`zh-TW` deployments** get correct behavior once the AAASM-5344 defect fix lands,
and first-party Taiwan recognizers thereafter — which no external provider offers
at all.

**Future contributors** get a stated boundary: the fast path decides, providers
advise, and the taxonomy is ours.

**Costs**: two detection paths to maintain; a second storage projection during
migration; per-locale recognizer maintenance; and a canonical model that must be
kept honest as adapters are added.

---

## Operational guidance

**Applies to v1:**

- Under `credential_action: Block`, `zh-TW` traffic is unsafe until the fix in
  [AAASM-5344](https://lightning-dust-mite.atlassian.net/browse/AAASM-5344)
  ships in `v0.0.1-rc.7`. Operators running Chinese-language agents should use a
  non-blocking `credential_action` until then.

**Deferred post-v1 (D-1) — there is no provider to operate in v1:**

- The deep path is **off by default**. Enabling it is an explicit configuration
  act.
- Pin provider artifacts by **digest**, never by mutable tag; verify signatures
  before use.
- Do **not** copy upstream Presidio's `docker-compose.yml` — it declares an
  `ollama` service that pulls models at runtime, so the stack never starts under
  egress-deny.
- Give provider workloads no egress. Verify with a negative test, not by
  inspection.
- Size a shared provider service for the cluster; do not multiply it per Pod.

---

## Validation requirements

**Enforceable in v1** — a reviewer can confirm this ADR is enforced by checking
that:

1. Conformance vectors cover CJK and full-width false-positive cases and pass.
2. All 26 existing vectors pass unchanged, with no golden vector edited to make a
   change pass.
3. A detection source returning crafted or out-of-range spans cannot cause raw
   content to be emitted — the existing fail-closed redaction test, which binds
   the in-process scanner just as much as any future adapter.
4. A metric-label cardinality test rejects `agent_id`, `destination`,
   `session_id` and fingerprints.
5. A counting test asserts the §8 worked example: three findings in one blocked
   action give `blocked_event_count = 1`, `blocked_finding_count = 3`.
6. A prevention-metric test asserts that absence of execution evidence prevents
   an event from counting as prevented.
7. A benchmark shows the fast path has not regressed against the numbers in the
   Spike report.
8. A detection source that cannot handle an input — unsupported locale, exceeded
   size ceiling, internal error — produces a recorded outcome distinguishable
   from "clean", and never a clean result. This is the v1-scoped form of the
   §4/§5 invariants and binds the in-process scanner today.
9. No detection source returns raw secret material to its caller; findings carry
   kind, span and label only.
10. No out-of-process or third-party provider implementation is reachable from a
    synchronous enforcement path — a compile-time or type-level boundary, not a
    convention. The port itself wrapping the in-process deterministic scanner is
    permitted and expected (see D-1).

**Deferred with §4–§7 (D-1)** — these cannot be satisfied in v1 because the thing
they validate does not exist. They become required when the follow-up provider
ADR is accepted:

- A negative egress test proves provider workloads cannot reach the internet.
- A **provider** capability miss and a **provider** timeout each produce a
  distinct recorded outcome, and neither produces a clean result (the
  in-process form of this is v1 item 8).
- An adapter test asserts no raw secret material appears in any adapter output.

---

## Reconsideration triggers

- A local engine appears whose small-payload latency is within ~10× of the Rust
  fast path, making synchronous provider consultation arguable.
- Presidio (or a successor) ships genuine `zh-TW` recognizers, changing the
  build-versus-adopt calculus for the locale pack.
- **A concrete, v1-shipped need for third-party engine coverage that the
  deterministic path cannot meet** — unstructured-PII NER is the likely trigger.
  This is what reopens **D-1**, via the follow-up provider ADR, and it is the
  most consequential trigger on this list.
- Measured deep-path value proves too low to justify the operational cost
  *(applies to the deferred provider work only)*.
- A provider compromise occurs in the wild, or a supply-chain incident affects a
  recommended provider *(applies to the deferred provider work only)*.
- The product commits to Kubernetes production orchestration, which would move
  §7 from analysis to specification.
- `RuntimeVerdict` is reopened for any other reason, making D-2 moot.
- Regulatory change requires retaining evidence this ADR currently forbids
  storing.

---

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-5269](https://lightning-dust-mite.atlassian.net/browse/AAASM-5269) | Spike that produced this ADR |
| [AAASM-5343](https://lightning-dust-mite.atlassian.net/browse/AAASM-5343) | records D-1/D-2/D-3 and moves this ADR to Accepted |
| [AAASM-5270](https://lightning-dust-mite.atlassian.net/browse/AAASM-5270) | parent Epic |
| [AAASM-5174](https://lightning-dust-mite.atlassian.net/browse/AAASM-5174) | shipped `/api/v1/scrub/*`; dashboard wiring outstanding |
| [Spike report](../research/AAASM-5269-sensitive-data-provider-architecture.md) | evidence, measurements, backlog |
| [ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md) | complements; invariants preserved |
| [ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) | owns the verdict vocabulary; D-2 keeps it frozen |
| [ADR 0024](0024-empty-cascade-semantics.md) | enum variants are not additive on the wire |
| [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) | constrains local transport and adapter loading |
| [ADR 0002](0002-sdk-security-boundary.md) | detection authority stays in trusted layers |
| [ADR 0006](0006-limited-self-host-k8s-terraform.md) | self-host scope for §7 |
| [AAASM-5344](https://lightning-dust-mite.atlassian.net/browse/AAASM-5344) | carries the D-3 `zh-TW` fix; ships in `v0.0.1-rc.7` |
| Implementation PRs | none yet — `B-1`/`B-2`/`B-3`/`B-4` exist as AAASM-5347/5344/5345/5346; the rest of the `B-` series is proposed, not created |
