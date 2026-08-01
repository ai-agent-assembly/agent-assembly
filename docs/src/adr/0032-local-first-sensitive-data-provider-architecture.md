# ADR 0032: Local-First Sensitive-Data Provider Architecture

**Status**: Proposed
**Date**: 2026-08
**Ticket**: [AAASM-5269](https://lightning-dust-mite.atlassian.net/browse/AAASM-5269)

This ADR records how Agent Assembly detects sensitive data: a deterministic
in-process fast path that stays authoritative for every synchronous decision, a
canonical provider-neutral finding model, and optional local-only providers
consulted asynchronously for large or high-risk payloads. It **complements**
[ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md), whose trust
boundary and fail-safety rules it preserves unchanged and whose reconsideration
trigger #2 ("an upstream classifier") invited it; it **defers to**
[ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) on the
verdict vocabulary and to
[ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) on the form
a local boundary may take. It supersedes nothing.

Supporting evidence, measurements and the full current-state survey are in
[the AAASM-5269 Spike report](../research/AAASM-5269-sensitive-data-provider-architecture.md).

> **Two decisions in this ADR are deliberately left open** — §D-1 (whether
> out-of-process providers are in scope for v1) and §D-2 (how the finer
> enforcement vocabulary relates to the frozen `RuntimeVerdict`). They are
> marked **PENDING** below and require product sign-off. Nothing in Phases 0–3
> depends on either.

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

- **A malicious or compromised provider.** It sees payload content by
  construction, so the mitigations are containment (no egress) and non-authority
  (its output is evidence, never a decision). It may also return crafted spans;
  redaction must remain fail-closed.
- **A local unprivileged user.** On a developer host, any local user can reach a
  `127.0.0.1` socket, and the kernel supplies no peer identity over loopback TCP
  — the reasoning ADR 0030 forbidden design #7 already recorded.
- **A supply-chain adversary.** Mutable image tags, unsigned artifacts and
  runtime model downloads are the delivery vectors.
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
| Where | in-process | in-process or (PENDING D-1) out-of-process |
| Timing | synchronous, pre-action | asynchronous |
| Authority | decides | advises; may trigger follow-up action |
| Budget | must not regress today's cost | bounded, cancellable |

Escalation is by risk class and payload size, never by default.

### 4. Providers are sensors with a declared capability set

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

Timeout, error, unavailability, capability miss and fallback are distinct
outcomes, each recorded. A deep-path failure never downgrades to "clean"; it
records the failure and leaves the fast-path decision standing. Because the
provider is off the synchronous path by §3, a deep-path failure cannot block an
action.

Note that Presidio returns an unhandled HTML 500 for oversized payloads *below*
its documented limit, so an adapter cannot distinguish "too large" from "crashed"
by status code; both map to `provider_error`, not to a clean result.

### 6. Local-only, egress-denied, and never a silent host modification

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

Use a **same-Pod sidecar** only when the provider's resident memory multiplied by
the replica count is acceptable *and* per-request latency is genuinely critical.
Otherwise use a **cluster-local shared service**. Presidio at 746 MiB fails the
first test and, being ineligible for the synchronous path, does not need the
second — Presidio is shared-service-only.

Docker Compose examples are in scope. Kubernetes production orchestration remains
a research question under [ADR 0006](0006-limited-self-host-k8s-terraform.md),
not committed implementation work.

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

### 10. PENDING — decisions requiring product sign-off

- **D-1 — are out-of-process providers in scope for v1?** Recommended: **no**.
  Phases 0–3 contain no provider and deliver the locale fix, the canonical model
  and the event layer without touching any accepted ADR. Out-of-process providers
  would be enabled by a follow-up ADR. Until D-1 is answered, §6's transport and
  §7's placement rules are **specifications, not commitments**.
- **D-2 — how does the finer enforcement vocabulary relate to `RuntimeVerdict`?**
  Recommended: keep ADR 0018's five-way enum frozen and carry
  `mask`/`tokenize`/`approval_*`/`shadow_only` in a separate additive
  `sensitive_data_disposition` field, since ADR 0024 establishes that adding an
  enum variant is not additive on the wire.

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
- **A provider sees payload content.** Containment (no egress) and non-authority
  bound the damage; they do not eliminate the exposure. Accepted only for
  operator-deployed local providers.
- **Deep-path findings arrive after the action.** By construction, asynchronous
  inspection cannot prevent the transmission it inspects. Its value is detection,
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
redacted and events from findings, and a truthful prevention metric. They take on
provider lifecycle if they opt into the deep path — Agent Assembly generates and
validates the assets but does not run the container runtime.

**SaaS** gains a bounded-cardinality metric surface and a tenant-scoped event
store. Deep-path providers are a per-tenant cost decision, not a platform default.

**SDK / CLI consumers** see no change. `CredentialKind` and the redaction labels
are frozen, so no vector, SDK or generated client moves.

**`zh-TW` deployments** get correct behavior once the Phase 0 defect fix lands,
and first-party Taiwan recognizers thereafter — which no external provider offers
at all.

**Future contributors** get a stated boundary: the fast path decides, providers
advise, and the taxonomy is ours.

**Costs**: two detection paths to maintain; a second storage projection during
migration; per-locale recognizer maintenance; and a canonical model that must be
kept honest as adapters are added.

---

## Operational guidance

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
- Under `credential_action: Block`, `zh-TW` traffic is unsafe until the Phase 0
  fix ships.

---

## Validation requirements

A reviewer can confirm this ADR is enforced by checking that:

1. No synchronous enforcement path can reach a provider — a compile-time or
   type-level boundary, not a convention.
2. Conformance vectors cover CJK and full-width false-positive cases and pass.
3. All 26 existing vectors pass unchanged.
4. A negative egress test proves provider workloads cannot reach the internet.
5. A provider returning crafted or out-of-range spans cannot cause raw content to
   be emitted — the existing fail-closed redaction test extended to adapter input.
6. A capability miss and a timeout each produce a distinct recorded outcome, and
   neither produces a clean result.
7. An adapter test asserts no raw secret material appears in any adapter output.
8. A metric-label cardinality test rejects `agent_id`, `destination`,
   `session_id` and fingerprints.
9. A counting test asserts the §8 worked example: three findings in one blocked
   action give `blocked_event_count = 1`, `blocked_finding_count = 3`.
10. A prevention-metric test asserts that absence of execution evidence prevents
    an event from counting as prevented.
11. A benchmark shows the fast path has not regressed against the numbers in the
    Spike report.

---

## Reconsideration triggers

- A local engine appears whose small-payload latency is within ~10× of the Rust
  fast path, making synchronous provider consultation arguable.
- Presidio (or a successor) ships genuine `zh-TW` recognizers, changing the
  build-versus-adopt calculus for the locale pack.
- Measured deep-path value proves too low to justify the operational cost.
- A provider compromise occurs in the wild, or a supply-chain incident affects a
  recommended provider.
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
| [AAASM-5270](https://lightning-dust-mite.atlassian.net/browse/AAASM-5270) | parent Epic |
| [AAASM-5174](https://lightning-dust-mite.atlassian.net/browse/AAASM-5174) | shipped `/api/v1/scrub/*`; dashboard wiring outstanding |
| [Spike report](../research/AAASM-5269-sensitive-data-provider-architecture.md) | evidence, measurements, backlog |
| [ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md) | complements; invariants preserved |
| [ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) | owns the verdict vocabulary (D-2) |
| [ADR 0024](0024-empty-cascade-semantics.md) | enum variants are not additive on the wire |
| [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) | constrains local transport and adapter loading |
| [ADR 0002](0002-sdk-security-boundary.md) | detection authority stays in trusted layers |
| [ADR 0006](0006-limited-self-host-k8s-terraform.md) | self-host scope for §7 |
| Implementation PRs | none yet — implementation is gated on this ADR |
