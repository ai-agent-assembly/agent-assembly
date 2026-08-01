# AAASM-5269 — Local-first sensitive-data provider architecture (Spike report)

**Ticket**: [AAASM-5269](https://lightning-dust-mite.atlassian.net/browse/AAASM-5269)
**Epic**: [AAASM-5270](https://lightning-dust-mite.atlassian.net/browse/AAASM-5270)
**Proposed ADR**: [ADR 0032](../adr/0032-local-first-sensitive-data-provider-architecture.md) (status `Proposed`)
**Surveyed against**: `main` @ `77bd2bf9`
**Date**: 2026-08

This is a research report. It recommends; it decides nothing. No production
behavior and no public contract is changed by the branch that carries it. Every
factual claim about the codebase carries a `path:line`; every performance claim
is either a measurement taken for this Spike (with its environment stated) or is
labelled an assumption.

---

## 0. Executive summary

The Epic asks whether to evolve the built-in credential scanner into a local-first
sensitive-data architecture that can consult optional self-hosted providers. The
answer is **yes, but the ordering the Epic implies is wrong**, for three reasons
the survey and benchmarks establish:

1. **The provider question is not the urgent one.** The measured behavior of the
   *existing* scanner on non-English input is a live defect (§4.1): 32 KB of
   ordinary Traditional-Chinese prose containing zero secrets produces **87**
   findings, and under `credential_action: Block` an agent communicating in
   Chinese is denied outright. No provider choice touches that code path. It
   should be fixed ahead of, and independently of, this architecture.

2. **External providers are disqualified from the synchronous path by physics,
   not by preference.** Presidio costs **12.28 ms** on a 592-byte tool call
   against the Rust scanner's **6.1 µs** — a ~2 000× ratio (§3.2) — and the
   out-of-process transport tax alone, with a provider that does no work at all,
   is 2.3× the entire current scan for that payload class (§3.3). The same
   providers are, however, entirely reasonable for large or high-risk payloads
   handled asynchronously. The economics therefore prescribe the architecture:
   **a deterministic in-process fast path, and an asynchronous deep path**.

3. **The audit and analytics half of the Epic is in worse shape than the
   detection half, and is the part that silently misinforms operators.** The
   durable audit table is write-only (§2.4), `CredentialLeakBlocked` does not
   mean "blocked" (§2.5), and an already-shipped API counts events where it
   claims to count findings (§2.6). A provider architecture layered on top of
   this would multiply, not fix, the problem.

The recommended architecture is **Option 2 — a Rust deterministic core with a
canonical finding model and optional local provider adapters** — delivered in
six phases, with the first two phases containing no provider at all.

Three items genuinely require Bryant's decision; they are in §10 and none of them
blocks the remaining research.

---

## 1. Existing Decision Summary

Required by `.claude/skills/adr-governance/SKILL.md` Step 4, produced before any
design work.

```
### Existing Decision Summary
- Applicable ADRs / recorded decisions:
  - ADR 0015 — DLP Trust Boundary, Redaction Fail-Safety & Heuristic Detection Limits.
    The binding prior decision. Owns the redaction fail-closed rule, the golden-vector
    protection, and the explicit acknowledgement that detection is heuristic.
  - ADR 0018 — Canonical Runtime Verdict & Enriched Decision Record. Freezes a 5-way
    `RuntimeVerdict` (`Allow`/`Narrow`/`Scrub`/`Pending`/`Deny`) as the single verdict
    vocabulary, and states that populating it alters the enforcement/audit-write hot
    path and therefore requires product + architecture sign-off first.
  - ADR 0002 — SDK Security Boundary. Detection runs authoritatively in trusted layers.
  - ADR 0030 — Developer Integration Boundaries & Local Trust Model. Forbidden design
    #8 bans dynamic shared-library loading / implicit registration inside the trusted
    process; #7 bans loopback TCP for a local control surface, on the grounds that it is
    reachable by every local user with no kernel-supplied peer identity.
  - ADR 0024 — Empty Cascade Semantics. Establishes that adding an enum variant is
    *not* additive on the wire.
  - ADR 0026 — Open Dashboard Product Semantics. Decision 3 remains open and this work
    forces it.
  - ADR 0006 / 0009 / 0010 — self-host scope, image-tag pinning, distribution examples.
- Prior decisions that bear on this change: all of the above. ADR 0015 is the parent
  decision; ADR 0018 owns the outcome vocabulary any new event must not duplicate;
  ADR 0030 constrains the *form* an out-of-process provider may take.
- Conflicts with what this change would do:
  - The Epic's requested enforcement-outcome vocabulary (`mask`, `tokenize`,
    `require_approval`, `approval_granted`, `approval_denied`, `shadow_only`,
    `error_fallback`) is strictly richer than ADR 0018's frozen five, and ADR 0024
    says a new variant is not additive on the wire. Resolution proposed in §6.3;
    escalated as D-2 in §10.
  - "Provider architecture" is ambiguous between in-process in-tree adapters and
    external processes. The former conflicts with nothing; the latter needs ADR 0030's
    constraints honoured explicitly. Escalated as D-1 in §10.
- Missing decisions this change forces: the fast-path/deep-path split, the provider
  trust boundary and transport, the canonical finding taxonomy, provider failure
  semantics, and the sensitive-data event/analytics model. None is recorded anywhere.
- Proposed ADR action: **create** — ADR 0032, complementing ADR 0015 and ADR 0018.
```

**Why `create` and not `supersede` or `amend`.** ADR 0015's own reconsideration
trigger #2 anticipates exactly this work ("an upstream classifier"), so this is
the successor it invited rather than a reversal of it. All five of its decisions
survive intact and become invariants of the new architecture — most importantly
the fail-closed redaction rule and the prohibition on editing a committed golden
vector to make a detector change pass (`0015:199-201`). Amending would bury a
cross-cutting deployment-topology decision inside a document about redaction
semantics. ADR 0030 set the precedent for the shape: it created a new ADR rather
than amending ADR 0002.

**Next unused ADR number is `0032`.** The index at `docs/src/adr/README.md:9`
says "0005 never existed"; git history says otherwise — `0005-sdk-only-gateway-access.md`
was created (`90679f35`) and withdrawn (`643700e5`), and `0028` was used twice
(`0989bf9a`, then `7b444d51`, retired in `bd867a23`). Both gaps stay permanently
empty. Highest existing is `0031`.

---

## 2. Current-state architecture

### 2.1 The pipeline, end to end

```
agent action
   │
   ├─► LAYER 1  SDK (aa-sdk-client, in-process, UNTRUSTED)
   │      PolicyQuery ──────────────────────────────┐   no scan on this path
   │      EventReport ─────────────────┐            │
   │                                   ▼            ▼
   ├─► LAYER 2  aa-proxy (MitM HTTPS)  │   aa-gateway  EngineInner::evaluate
   │      scans body PRE-forward       │     engine/mod.rs:889  (sync fn)
   │      probe_adjudication.rs:143    │     Stage 6: self.scanner.scan(text)
   │      ForwardedPayload::NotForwarded     engine/mod.rs:1438  built-in + policy
   │      ── proves non-transmission          patterns merged → one findings list
   │                                   │            │
   │                          aa-runtime pipeline   │
   │                          pipeline/mod.rs:127   │
   │                          RuntimeScanner — runs ONLY on EventReport
   │                          i.e. POST-action, not pre-action
   │                                   │            │
   │                          enforcement.rs:268-271
   │                          *field = result.redact(field)
   │                                   │            │
   └─────────────────────────────────► ▼ ◄──────────┘
                                  AuditEntry
                                  (+ Redaction{credential_findings, redacted_payload})
                                       │
                    ┌──────────────────┴───────────────────┐
                    ▼                                      ▼
         per-session JSONL                    audit_bridge.rs:84-95
         hash-chained, full fidelity          audit_entry_to_storage_event
                    │                         ── 14 fields lost ──
                    │                                      ▼
                    │                            durable audit_events table
                    │                            query_audit_events: NO non-test caller
                    │                                    (write-only)
                    ▼
         analytics re-scan JSONL per request
         analytics.rs:373 — capped at 100 000 events
                    │
                    ▼
         GET /api/v1/analytics/agent-enforcement
         GET /api/v1/scrub/{patterns,pattern-counts,posture}
                    │
                    ▼
         dashboard — NOT wired to /scrub/* (§2.7)
```

### 2.2 The detector inventory

`aa-security` uses **no regex at all** — `aho-corasick = "1"` is its only
detection dependency (`aa-security/Cargo.toml:10`). Detection is five passes
(`scanner.rs:552`): an Aho-Corasick literal-prefix pass over 18 patterns, a
digit-sequence pass (credit card + US SSN), an email pass, a high-entropy pass,
and an Azure `AccountKey=` pass.

`CredentialKind` has 27 variants, each with a `category()`, a `severity()` and an
`as_str()` redaction label (`scanner.rs:95-196`). Those labels are a **public
contract**: they appear in `[REDACTED:<kind>]` output pinned by 26 conformance
vectors, and `CredentialKind::ALL` is exposed over HTTP by the shipped
`/api/v1/scrub/patterns`.

PII coverage is exactly three detectors — `CreditCardLuhn`, `EmailAddress`, and a
US-only `SsnPattern`. **There is no Taiwan identifier of any kind, and no
non-US PII.**

The four dashboard fixture patterns with no detector at all are confirmed:
`AWS_SECRET`, `JWT`, `INTERNAL_URL`, `PHONE`.

### 2.3 Fail-open / fail-closed, and where enforcement actually happens

The single most consequential correction the survey produced:

> **`aa-runtime`'s scanner is post-action.** `RuntimeScanner` runs only on
> `IpcFrame::EventReport` (`aa-runtime/src/pipeline/mod.rs:127`). The pre-action
> `PolicyQuery` path never scans locally.

So despite `aa-runtime` being described as "the authoritative enforcement point",
the genuinely **pre-transmission** points are the **gateway** (`engine/mod.rs`
Stage 6, before a decision is returned) and the **proxy** (before
`dial_upstream_tls`). This matters directly for the Epic's requirement that an
event may only be called "prevented" when transmission provably did not occur
(§6.5).

Related behaviors worth recording, each verified:

| Behavior | Evidence | Consequence |
|---|---|---|
| `redact_only` — the default — collapses to a hard **deny** on the SDK path | `aa-runtime/src/pipeline/mod.rs:656-671` | the default action is more severe than its name |
| the gateway's redacted payload never reaches the wire | `convert.rs:179` emits `"$.{kind:?}"`, a JSONPath | redaction is signalled, not delivered, on that path |
| `ScannerConfig` has **zero production callers** | grep across workspace | the `disabled` kill switch and the literal custom-pattern slot are unreachable |
| the proxy's JSONL audit writer is never instantiated in production | `aa-proxy/src/lib.rs:70` → `proxy/mod.rs:172` passes `None` | proxy findings never reach disk |
| redaction fails **closed** on an unspliceable span | `scanner.rs:443-461`, returns `"[REDACTED]"` | correct, and required by ADR 0015 |

### 2.4 The audit/storage bridge — the ticket's claim, confirmed and exceeded

`aa-gateway/src/storage/audit_bridge.rs:84-95`:

```rust
AuditEvent {
    ts:               ts_from_ns(entry.timestamp_ns()),
    event_id:         event_id_for_entry(entry),
    agent_id:         entry.agent_id(),
    team_id:          entry.team_id().map(str::to_string),
    action:           entry.event_type().as_str().to_string(),   // ← same source
    decision:         entry.event_type().as_str().to_string(),   // ← same source
    dry_run:          false,                                     // ← hardcoded
    shadow_decision:  None,                                      // ← hardcoded
    matched_rule_id:  None,                                      // ← hardcoded
    payload,
}
```

The ticket's assertion is verbatim correct, and understates the loss. The full
inventory is 14 items; the ones that matter for this Epic:

| Field | In `AuditEntry` / JSONL | In durable `AuditEvent` | Lost? |
|---|---|---|---|
| `credential_findings` | yes (kind + offset + label) | **absent** | **total** |
| `redacted_payload` | yes | **absent** — the *raw* payload is what persists | **total, and a privacy regression** |
| hash chain | yes | absent | total |
| `root_agent_id`, `parent_agent_id`, delegation depth | yes | absent | total |
| `org_id` | yes | absent | total |
| `session_id` | yes | absent | total |
| `policy_doc_id` | yes | absent | total |
| `action` vs `decision` | distinct concepts | both = event type | conflated |
| `dry_run` / `shadow_decision` / `matched_rule_id` | available | constant | fabricated |

Two consequences:

- **The durable table is write-only.** `query_audit_events` and
  `count_audit_events` have no non-test caller anywhere in the workspace. Every
  analytics endpoint re-scans the JSONL files per request, capped at 100 000
  events (`analytics.rs:373`) — and `get_agent_enforcement` calls the
  *non*-truncation-aware fetch, so it can silently return partial counts even
  though a `truncated` flag exists.
- **The persisted payload is the raw one, not the redacted one.** That is a data
  -minimisation defect in its own right, independent of this Epic.

### 2.5 `CredentialLeakBlocked` does not mean blocked

| Configured action | Recorded event type | What actually happened |
|---|---|---|
| redact | `CredentialLeakBlocked` | payload scrubbed and **forwarded upstream** |
| hard block | `PolicyViolation` | action denied |
| `alert_only` | `ToolCallIntercepted` | findings present, counted as a clean allow |

Any current figure derived from `CredentialLeakBlocked` is measuring redactions,
most of which resulted in **successful transmission** of scrubbed bytes. A
dashboard tile reading "leaks blocked" from this is wrong in the most dangerous
direction — it reports prevention where there was forwarding.

### 2.6 Event-versus-finding conflation is already shipped

`GET /api/v1/scrub/pattern-counts` counts **alerts by their first kind**, not
findings by kind. An action containing one AWS key and three emails increments
one bucket by one. The distinction this Spike is asked to define is therefore not
merely a future design concern — it is a live inaccuracy in a shipped API.

Separately, `agent-enforcement` never inspects `dry_run`, while
`transform_for_observe_mode` rewrites `Deny → Allow` before the event type is
chosen. Observe-mode decisions are counted as real enforcement, and errors occur
in both directions.

### 2.7 AAASM-5174 — the Epic's premise is out of date

The backend **shipped**. `aa-api/src/routes/scrub.rs` exists; the three routes are
registered at `aa-api/src/routes/mod.rs:263-265` and specified at
`openapi/v1.yaml:3378`, `:3413`, `:3441`.

The dashboard was **never wired to them**. `dashboard/src/` contains only the
generated `schema.d.ts` types; no component issues a request. And the page still
explains itself in the present tense using the now-false premise —
`dashboard/src/pages/ScrubPage.tsx:29-34`:

> "…has no route in `aa-api` at all (no `scrub`, `dlp`, `redact`, `pattern` or
> `leak` path exists in `openapi/v1.yaml`) and renders as an explicit absence
> carrying its reason."

and `dashboard/src/features/scrub/posture.ts:14-18`:

> "They are `not-supported` rather than `unknown` because waiting will not help:
> there is no DLP endpoint in `aa-api` at all…"

Three such paths now exist. This is an **inverted truthfulness defect**: the page
declines to answer questions the backend can now answer, and justifies the
refusal with a statement that is no longer true. AAASM-5112 and AAASM-5156 are
genuinely complete; they were frontend-only honesty fixes and are not implicated.

**Proposed disposition of AAASM-5174: remains valid, SPLIT.** The backend half is
correctly `Done`. The dashboard-wiring half was never ticketed and is now a
correctness issue rather than a gap. See §9 backlog item `B-1`.

### 2.8 The regression net

The binding compatibility contract is **26 conformance vectors** in
`conformance/vectors/credential_detection/`, plus ADR 0015's rule that a
committed golden vector must not be edited to make a detector change pass
(`0015:199-201`). The vectors assert start offsets and kinds directly; **all**
end-span and coalescing behavior is pinned indirectly, through exact
`expected_redacted` strings. Five of the 27 kinds have no vector at all, and
`aa-security/src/redaction.rs` has zero tests.

There is exactly **one** perf gate on the hot path (`engine/mod.rs:3749`).

---

## 3. Measured performance

### 3.1 Environment

Apple M3 Max (16 cores), 128 GB, macOS 26.4.1, `rustc 1.97.0 (2d8144b78 2026-07-07)`,
release profile. Presidio in Docker Desktop 28.3.2 (linux/aarch64 VM, 4 vCPU /
7.75 GiB) with `--memory=4g`. Commit `77bd2bf9`. Every fixture is synthetic.

Reproduce with:

```bash
cargo bench -p aa-security --bench spike_5269_payload_classes    # criterion, throughput
cargo bench -p aa-security --bench spike_5269_percentiles        # true p50/p95/p99
```

Both bench targets are committed on this branch. They assert nothing and gate
nothing.

### 3.2 The built-in Rust fast path

| payload | bytes | findings | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| small tool call, 1 finding | 449 | 1 | **6.13 µs** | 6.29 µs | 7.50 µs |
| small tool call, clean | 410 | 0 | **5.00 µs** | 5.13 µs | 5.92 µs |
| medium prompt, 32 KB | 32 954 | 4 | **394 µs** | 416 µs | 433 µs |
| medium prompt, 32 KB, clean | 32 800 | 0 | 434 µs | 468 µs | 508 µs |
| large document, 1 MB | 1 049 045 | 6 | **12.47 ms** | 13.67 ms | 14.47 ms |
| mixed zh-TW, 32 KB | 32 953 | **91** | 407 µs | 420 µs | 443 µs |
| mixed zh-TW, 32 KB, *clean* | 32 799 | **87** ← see §4.1 | 396 µs | 417 µs | 439 µs |
| high density, 500 findings | 59 300 | 600 | **956 µs** | 1.11 ms | 1.12 ms |

`CredentialScanner::new()` costs 132 µs p50 — a per-process fixed cost, not a
per-request one.

Run-to-run variance on an unquiesced laptop is roughly ±10% at the p50 and
larger at the max (background load produces occasional millisecond outliers, as
the `max` column shows). The conclusions below depend on ratios spanning two to
three orders of magnitude, so none of them is sensitive to that.

Three conclusions:

- Throughput is a near-constant **~80 MiB/s** across three orders of magnitude,
  i.e. cost is linear in bytes. For an Aho-Corasick automaton that is slow; the
  dominant cost is the entropy/digit/email passes, not the AC pass.
- **Finding count matters more than size.** 500 findings in ~58 KB costs 956 µs
  against 394 µs for 32 KB with 4 findings — a penalty driven by the sort and
  overlap-coalescing tail rather than by input length.
- Redaction adds ~5% on top of the scan, so the interesting budget is detection.

### 3.3 Out-of-process transport floor

Measured with a stand-in provider that parses the request and returns an empty
finding list — **no detection whatsoever**. These are lower bounds for any
out-of-process design.

| payload | JSON encode+decode only | loopback TCP, persistent | TCP, new conn/req | UDS, persistent |
|---|---:|---:|---:|---:|
| ~450 B | 0.71 µs | **14.12 µs** | 43.29 µs | **6.62 µs** |
| 32 KB | 14.33 µs | 33.67 µs | 55.54 µs | 42.25 µs |
| 1 MB | 445 µs | 536 µs | 579 µs | 1.06 ms |

Set against §3.2, this is the decisive result of the Spike:

| payload | in-process scan | transport tax alone | tax as % of scan |
|---|---:|---:|---:|
| small tool call | 6.1 µs | 14.1 µs (TCP) / 6.6 µs (UDS) | **230%** / 108% |
| 32 KB | 394 µs | 33.7 µs | 9% |
| 1 MB | 12.5 ms | 536 µs | 4% |

**Transport overhead dominates precisely where the synchronous enforcement path
lives, and is negligible precisely where deep inspection is actually wanted.**
The architecture follows from the numbers rather than from taste.

Note also that UDS beats TCP by 2× for small payloads but loses by 2× at 1 MB
(buffer sizing), and that a fresh connection per request triples small-payload
cost — so a provider transport must be a persistent connection.

### 3.4 Presidio Analyzer, measured

Image `ghcr.io/data-privacy-stack/presidio-analyzer:latest`.

| metric | measured |
|---|---|
| idle RSS | **746 MiB** (752 MiB after load) |
| cold start to `healthy`, **egress denied** | **5.4 s** |
| supported entities | 19, all US/UK-centric |
| image size (compressed, amd64) | 566 MB, of which one 409 MB layer is the spaCy model |

For scale, `aa-runtime:latest` is a **6.8 MB** image; one Presidio replica's
resident memory is ~110× that.

Latency, same payload classes:

| payload | Rust in-process p50 | Presidio p50 | ratio |
|---|---:|---:|---:|
| small tool call (~592 B) | 6.1 µs | **12.28 ms** | **~2 000×** |
| medium prompt 32 KB | 394 µs | **613 ms** | **~1 600×** |
| large document 1 MB | 12.5 ms | **HTTP 500** | — |

Scaling is superlinear and then hits a wall:

| bytes | result | latency |
|---:|---|---:|
| 65 564 | OK, 443 findings | 1 524 ms |
| 131 128 | OK, 886 findings | 3 830 ms |
| 262 256 | OK, 1 772 findings | **11 331 ms** |
| 524 364 | **HTTP 500** (bare HTML) | — |
| 1 048 580 | **HTTP 500** `[E088] Text of length 1048580 exceeds maximum of 1000000` | — |

Only the last is a documented limit (spaCy's `nlp.max_length`). The 524 KB and
786 KB failures are *below* that limit and return an unhandled HTML 500 — so **an
adapter cannot distinguish "too large" from "crashed" by status code**, which
bears directly on fail-open/fail-closed semantics.

**Local-first is satisfied.** On a `docker network create --internal` network
Presidio reached `healthy` in 5.4 s, served a real `/analyze` request from inside
the network, and could not reach `https://pypi.org` (`URLError`). Models are baked
into the image. The caveat is that upstream's own `docker-compose.yml` adds an
`ollama` service that pulls models at runtime, so that compose file must not be
copied.

### 3.5 Unmeasured, with a plan

| Item | Why not measured | How to measure |
|---|---|---|
| provider concurrency / queueing | single-client only | `wrk`-style N-client harness against the container; report saturation point |
| Gitleaks per-invocation spawn cost | binary not installed; no server mode exists | install pinned release, time `gitleaks detect --no-git` over the same fixtures |
| same-Pod sidecar vs cluster-local hop | no cluster available | k3d/kind two-node; compare loopback vs ClusterIP p99 |
| sidecar-per-Pod memory amplification | as above | arithmetic from §3.4 idle RSS × replica count; 20 pods ≈ 15 GB vs ~750 MB shared |
| Presidio Anonymizer | only Analyzer exercised | same harness against `/anonymize` |

The 4 vCPU Docker VM understates a production host, so Presidio's absolute
latencies are pessimistic. The **ratios** against the Rust path, taken on the same
machine, are the durable result.

---

## 4. Language and locale

### 4.1 Defect: Traditional Chinese is systematically misclassified as secrets

Found while building the benchmark; root-caused and independently reproduced.

32 KB of benign `zh-TW` prose containing **zero** planted secrets yields **87**
`GenericHighEntropy` findings. The byte-equivalent English yields **0**.

| input | findings | `redact()` output |
|---|---:|---|
| `請查詢訂單編號：ORD20260427001 的狀態` | 1 | `[REDACTED:GenericHighEntropy] 的狀態` |
| `please look up order id: ORD20260427001 status` | 0 | *unchanged* |
| `聯絡電話：0912-345-678，請於上班時間撥打` | 1 | `[REDACTED:GenericHighEntropy]` — the whole string |
| `文件連結：https://example.com/docs/guide 請參考` | 1 | `[REDACTED:GenericHighEntropy] 請參考` |

Measured false-positive rate by Han-character run length (2 000 trials each):

| Han chars | FP rate |
|---:|---:|
| 13 | 50.5% |
| 17 | **93.9%** |
| 20 | 99.5% |

**Cause** — three individually reasonable lines in `aa-security/src/scanner.rs`:

1. `:963` `text.split_whitespace()` — Chinese does not delimit words with spaces,
   so one "token" is an entire clause.
2. `:966-967` `let len = token.len();` gated at `(20..=64)` — `str::len()` is
   **bytes**, and a Han character is 3 UTF-8 bytes, so a 7-character Chinese
   phrase already sits inside the "looks like a secret" window.
3. `:878-894` `shannon_entropy` counts over `s.as_bytes()` while its own doc
   comment at `:896` calls the result "bits per **character**" — an equivalence
   that holds only for ASCII. Han characters spread bytes widely, so byte entropy
   lands at 4.6–4.9 against the `ENTROPY_BITS_GATE = 4.5` threshold (`:903`).

The gate's calibration note names its corpus (`:899`): *"…while **English prose**
and `snake_case` / `kebab-case` identifiers stay below this."* The assumption was
documented, English-only, and never revisited.

**End-to-end impact.** On the enforcement path
(`aa-runtime/src/pipeline/enforcement.rs:268-271`, `*field = result.redact(field)`),
`客戶反映系統登入失敗請協助處理謝謝` becomes `[REDACTED:GenericHighEntropy]`. Under
`credential_action: Block`, an agent communicating in Chinese is **denied
outright**. The failure is language-discriminatory and generalises to every
space-less script — Chinese (both scripts), Japanese, Thai. It also floods the
audit trail: each false positive is a real `CredentialFinding` flowing into
`Redaction`, the audit entry and the alert store, so any "leaks detected" figure
for a `zh-TW` tenant is dominated by noise.

**Why it survived.** `rg '[\x{4e00}-\x{9fff}]' conformance/ aa-security/` returns
nothing on `main`. All 26 vectors are ASCII. The suite *does* carry a
false-positive guard — `entropy_false_positive_clean.json` — but its input is
`"The quick brown fox jumps over the lazy dog. This is a normal log message with
no secrets."` A `zh-TW` sibling would have caught this on the day the gate landed.

**Proposed fix — one line, no contract change**: skip tokens containing any
non-ASCII byte in the entropy pass. A base64 or hex secret is ASCII by
definition, so this weakens no detection and breaks no vector. It belongs to a
**Bug ticket sequenced ahead of the ADR** (§9, `B-2`), because no architecture
choice affects this code path.

This report deliberately does **not** add the CJK conformance vector: written
truthfully it fails against current behavior and would turn CI red from a
research ticket; written to match current behavior it would enshrine the defect.
It is the fix ticket's regression test.

### 4.2 Two further defects in the same area

- **Full-width digits are invisible.** `４５３２…` (U+FF10–19) is not seen by
  `CreditCardLuhn` or `SsnPattern`. This is a live evasion and is not `zh-TW`
  specific.
- **`String::from_utf8_lossy` + `into_bytes()` write-back**
  (`aa-runtime/src/pipeline/enforcement.rs:288-292`) corrupts chunk-split CJK
  payloads.

A hypothesis worth recording as **refuted**: byte offsets cannot slice a CJK
codepoint mid-character, because every detector predicate is ASCII-only and UTF-8
guarantees ASCII bytes never appear inside a multi-byte sequence. `redact()`
additionally guards with `is_char_boundary`.

### 4.3 Taiwan entity catalogue — deterministic vs probabilistic

| Entity | Format | Validation | Tier |
|---|---|---|---|
| 國民身分證統一編號 | 1 letter + 9 digits | letter→2-digit map + weighted mod-10 | **deterministic** |
| 居留證 (2021 form) | 1 letter + 9 digits, `d₁ ∈ {8,9}` | **identical algorithm** to national ID | **deterministic** |
| 居留證 (legacy) | 2 letters + 8 digits | separate map | **deterministic** |
| 統一編號 (business) | 8 digits | weighted checksum; **changed mod-10 → mod-5 on 2023-04-01** | **deterministic** |
| Mobile | `09xx-xxx-xxx`, `+886 9…` | format only, no checksum | deterministic (weak) |
| Landline | `0x-xxxxxxxx` by area code | format only | deterministic (weak) |
| Address | 縣/市/區/路/段/巷/弄/號/樓 | structural | partial / probabilistic |
| Chinese personal name | 2–4 chars | surname gazetteer + context | **probabilistic** |
| 健保卡號 | — | no stable public algorithm | **not reliably detectable** |

Two traps worth calling out because they cause silent misses:

- The 2021 ARC uses the *same* algorithm as the national ID and differs only by
  the first digit, so a naive `d₁ ∈ {1,2}` filter **silently misses every foreign
  resident**.
- 統一編號 changed to mod-5 on 2023-04-01, so a legacy-only detector **misses
  every business registered since**.

Residual false-positive rates are real and must be stated rather than hidden:
統一編號 ~22% of random 8-digit strings pass the checksum; national ID ~10%;
phone and passport have no checksum at all. Context keywords (身分證/統編/電話)
are what make these usable, not the checksum alone.

### 4.4 `\b` does not work against CJK

Han is `\p{Alphabetic}`, therefore `\w`, so `\b\d{8}\b` **does not match**
`統編12345675` — which is exactly how the identifier is written in practice.
Rust's `regex` has no lookaround, so boundary checking must be manual
(`!c.is_ascii_alphanumeric()`), not `\b`. This affects `aa-gateway`'s policy
patterns (`regex = "1"`, Unicode defaults on) as well as any new recognizer.

### 4.5 What the providers offer for zh-TW: nothing

Measured, not inferred:

| request to Presidio | result |
|---|---|
| `language: "zh"` | **HTTP 500** `{"error":"No matching recognizers were found to serve the request."}` |
| `language: "zh-TW"` | **HTTP 500**, same |
| Chinese text as `language: "en"` | **HTTP 200, 0 findings** |

The third row is the dangerous one: Presidio does not error, it returns a *clean*
result. An adapter that falls back to `en` on an unsupported locale would report
"no sensitive data" for every Chinese payload. **An unsupported locale must be an
explicit capability miss, never a clean scan.**

Taiwan identifiers, submitted as `en`, are confidently mislabelled:

| synthetic input | Presidio returns |
|---|---|
| `身分證字號 A123456789` | `US_DRIVER_LICENSE(0.30)` |
| `統一編號 12345675` | `US_BANK_NUMBER(0.05)`, `US_DRIVER_LICENSE(0.01)` |
| `手機 0912345678` | **`DATE_TIME(0.85)`**, `PHONE_NUMBER(0.40)` |

Note the last row: the *highest-confidence* label is `DATE_TIME`. A "take the
top-scoring entity" adapter would classify a Taiwanese phone number as a
timestamp.

Presidio's catalogue includes Thailand, Korea, Singapore and the Philippines but
**no Taiwan and no Chinese recognizers**. `zh_core_web_*` models are
Simplified-trained on OntoNotes 5 (`sm` 46 MB / F 68.42; `trf` 396 MB / F 74.26),
giving a realistic zh-TW estimate of ~0.62–0.70 — and `zh_core_web_lg` alone is a
603 MB wheel. Gitleaks has no locale dimension and no PII scope at all.

**Conclusion: Taiwan detection must be first-party Rust.** It is regex plus
arithmetic plus a ~60-word context dictionary and a 22-entry gazetteer — no model
is required — and it is the only option that can run in the in-process SDK layer
and in WASM, where Presidio cannot run at all.

**Taxonomy recommendation**: locale-qualified `NATIONAL_ID[zh-TW/arc_new]` rather
than new `CredentialKind` variants, so policies need no per-locale rewrite and
`CredentialKind::ALL` — now a published API surface — stays stable.

---

## 5. Provider feasibility

### 5.1 Matrix

| | **Built-in Rust** | **Presidio** | **Gitleaks** | **Custom local protocol** |
|---|---|---|---|---|
| License | product-owned | MIT | MIT | product-owned |
| Governance | us | **`data-privacy-stack`, community-run — no longer Microsoft** | zricethezav/gitleaks | us |
| Invocation | in-process library | HTTP service | CLI, file-oriented | our choice |
| Small-call latency | **6 µs** | **12.3 ms** | process spawn (unmeasured) | transport floor 6.6–14 µs |
| Large payload | 12.5 ms @ 1 MB | **fails ≥ 524 KB** | file-oriented, fine | n/a |
| Idle RSS | ~0 (shared automaton) | **746 MiB** | ~0 between invocations | provider-defined |
| Offline / egress-deny | native | **verified working**, models baked in | native | by construction |
| zh-TW | none today; **buildable** | **none, and fails closed-clean** | n/a (secrets only) | by construction |
| Offsets | byte offsets | char offsets | **line/column** | mandate byte offsets |
| Confidence | none (binary) | 0–1 score, poorly calibrated outside US | **none** (entropy only) | mandate a band |
| Returns raw secret? | **no** | n/a (PII spans) | **YES by default** — `Finding.Secret` unless `--redact=100` | **forbid** |
| Attestations | n/a | SPDX SBOM + SLSA provenance | SLSA provenance, **no SBOM** | n/a |
| Sync pre-action | **yes** | **no** | no | only in-process |
| Async deep path | yes | **yes, with a size ceiling** | yes | yes |

### 5.2 Rejected candidates

- **TruffleHog** — AGPL-3.0, *and* its headline feature is outbound credential
  verification, which is a direct violation of the local-first constraint.
- **detect-secrets** — Python runtime for a strict subset of Gitleaks' coverage.
- **ripsecrets** — stale; port the rules instead of taking the dependency.
- **Presidio transformers/GLiNER extras** — runtime Hugging Face downloads break
  egress-deny.
- **Presidio as a per-Pod sidecar** — ~15 GB resident across 20 pods versus
  ~750 MB for one shared service, for a provider that must not be on the
  synchronous path anyway.

### 5.3 Deployment topologies

| Topology | Isolation | Latency | Amplification | Verdict |
|---|---|---|---|---|
| in-process Rust | none (same address space) | **0** | none | **fast path — default and always available** |
| local child process | process | ~7 µs UDS | 1× per host | good for a custom provider |
| container, Docker Compose | container | ~14 µs loopback | 1× per host | **the self-host example shape** |
| **same-Pod sidecar** | container, shared netns | loopback | **× replica count** | only for tiny providers; **never Presidio** |
| **cluster-local Deployment** | pod + network | real network hop | 1× per cluster | **the K8s answer for heavy providers** |
| node-local DaemonSet | pod | loopback-ish | × node count | middle ground; not needed at current scale |
| external user-managed | full | unbounded | user's problem | allow, validate only |

**Decision rule.** Use a **same-Pod sidecar** only when the provider's resident
memory is small enough that multiplying it by the replica count is acceptable
*and* per-request latency is genuinely critical. Otherwise use a **cluster-local
shared service**. Presidio at 746 MiB fails the first test and, being ineligible
for the synchronous path, does not need the second — so Presidio is
**shared-service-only**.

Per repo policy, Helm/Terraform/Kubernetes production orchestration is a
research/ADR question here, not committed implementation work. Docker Compose
examples are in scope.

### 5.4 Provider lifecycle — automate vs validate

The boundary matters more than the mechanism.

| Concern | Agent Assembly should |
|---|---|
| declarative provider manifest | **own** — schema, parsing, validation |
| capability discovery | **own** — query, cache, expose |
| image/artifact resolution | **generate** assets and **validate** digests; never pull silently |
| digest / signature verification | **own** — verify before use, fail closed |
| start / stop / restart | **validate and report only** for containers; may own a child process it spawned |
| readiness / liveness / smoke test | **own** |
| resource reporting | **own** |
| upgrade / rollback | **generate** the change; the operator applies it |
| runtime egress policy | **generate** and **verify**, deny-by-default |
| installing Docker, obtaining root, `pip install` | **never** |

ADR 0030's forbidden designs constrain the *form* rather than prohibiting
out-of-process providers, and two of them point the design in a specific
direction:

- **#8** bans dynamic shared-library loading and `inventory`-style registration
  *inside the trusted process*. This argues **for** out-of-process providers over
  in-process dynamic plugins — an external sensor is precisely not unreviewed
  code in the trusted address space.
- **#7** bans loopback TCP for a local control surface, because it is reachable
  by every local user with no kernel-supplied peer identity. Applied here, a
  local provider transport should be a **Unix domain socket with peer-credential
  checks**, not `127.0.0.1:port`. The measurement in §3.3 independently favours
  UDS for small payloads, so security and performance agree.

### 5.5 Threat model

| Threat | Mitigation |
|---|---|
| provider compromised, returns crafted spans | spans validated against payload length and char boundaries; redaction already fails closed (`scanner.rs:443-461`) |
| provider compromised, exfiltrates payload | egress deny-by-default (verified achievable, §3.4); no provider gets network |
| provider unavailable / times out | explicit per-risk-class policy; never silently "clean" |
| provider returns raw secret (Gitleaks default) | **adapter must set `--redact=100`**; adapter rejects any response containing raw match text |
| unsupported locale treated as clean | **capability miss ≠ clean scan** (§4.5) |
| malicious image / tag mutation | digest pinning + signature verification before use |
| socket reachable by other local users | UDS + peer credentials, `0600`, per-instance path |
| span mismatch corrupts payload | existing fail-closed path; property test across scripts |
| raw values leak into logs/metrics/traces | prohibited by construction; §6.4 |

---

## 6. Sensitive-data event and analytics model

### 6.1 What the current system can and cannot answer

The Epic's motivating question — *"how many findings of each class did Agent X
attempt to send to Tool Y, how many were blocked versus redacted, and how many
were uncertain?"* — **cannot be answered today**, and not for one reason but four:

1. findings never reach durable storage (§2.4);
2. destination/tool is not a dimension of the audit event at all;
3. "blocked" and "redacted" are not distinguishable from the event type (§2.5);
4. there is no notion of uncertainty — findings are binary.

### 6.2 The three proposed records

`SensitiveDataDecisionEvent` (one per inspected action), `SensitiveDataFindingRecord`
(child rows), and `SensitiveDataAnalyticsRollup` (pre-aggregated). Full field
lists, Rust sketches, JSON examples and SQL shapes are carried in the ADR; the
load-bearing choices are:

- **Findings become normalized child rows**, not JSON blobs — because every
  headline metric groups by category, and a JSON blob cannot be indexed for that
  without a second projection.
- **The event carries `finding_count` and `finding_count_by_category`**
  denormalized, so the common dashboard query needs no join.
- **Schema version is explicit** on every record.

### 6.3 Outcome vocabulary — the ADR 0018 interaction

ADR 0018 froze a 5-way `RuntimeVerdict` and ADR 0024 established that adding an
enum variant is not additive on the wire. The Epic's requested vocabulary is
richer. Extending the frozen enum would be a breaking wire change to a
deliberately frozen contract.

**Proposed resolution**: keep `RuntimeVerdict` as the coarse, frozen, wire-visible
verdict, and carry the finer vocabulary in a **separate additive field**,
`sensitive_data_disposition`, on the new event only. `Scrub` remains the
`RuntimeVerdict` for every transforming disposition; the new field distinguishes
`redact` / `mask` / `tokenize` beneath it. Nothing about ADR 0018 or 0024 has to
move. Escalated as **D-2** because it is a public-contract shape, not purely a
technical call.

### 6.4 Privacy-safe evidence

- **Raw values never enter** logs, metric labels, traces, or dashboard payloads.
  This is unconditional.
- **Offsets and lengths are not automatically safe.** A length plus a category
  can identify a value in a small domain, and an offset into a known template can
  help reconstruct it. Recommendation: offsets/lengths in the tamper-evident
  audit tier only; **never** in the analytics projection or any API response.
- **Field paths are safe** and are the right drill-down granularity.
- **Tenant-keyed HMAC fingerprints are rejected for PII.** A Taiwan national ID
  has ≈5.2 × 10⁸ candidates — enumerable in **under a second on one GPU** given
  the tenant key. Fingerprinting is only defensible above roughly 80 bits of
  value entropy, which excludes every PII category and admits only long random
  secrets. This must not be offered as a general "repeat exposure" feature.
- **Cardinality**: the allowed metric label set is `{category, severity,
  confidence_band, outcome, detection_method, provider_id}` — all bounded.
  `agent_id`, `destination`, `session_id`, `trace_id` and any fingerprint are
  **forbidden as metric labels** and belong to the queryable event store.
- **Sampling**: high-risk findings and every enforcement failure are never
  sampled. Clean allow events may be sampled or rolled up.

### 6.5 The prevention rule

An event may be counted as **prevented transmission** only when all four hold:

1. the enforcement point is pre-transmission (gateway or proxy — **not**
   `aa-runtime`, §2.3);
2. the decision was `deny` or a transforming disposition;
3. an explicit execution-evidence observable records that the action did not
   reach its destination;
4. the action was not in observe/dry-run mode.

The observable in (3) **already exists**: `ForwardedPayload::NotForwarded`
(`aa-proxy/src/probe_adjudication.rs:143`), returned before the sole
`dial_upstream_tls`. It is currently confined to the probe reply and never
persisted. Persisting it is the smallest change that makes a truthful prevention
metric possible.

Everything else is **detected**, not prevented. Note that redaction *forwards*
scrubbed bytes, so a redacted action is a transformed transmission, not a
prevented one — a distinction the current `CredentialLeakBlocked` naming actively
obscures.

### 6.6 Metric dictionary

| Metric | Numerator | Denominator |
|---|---|---|
| `inspected_action_count` | actions that completed inspection | — |
| `inspection_coverage_rate` | inspected eligible actions | eligible actions observed |
| `event_count` | decision events | — |
| `finding_count` | finding records | — |
| `blocked_event_count` | events with outcome `block` | — |
| `blocked_finding_count` | findings **contained in** blocked events | — |
| `redacted_event_count` | events with a transforming disposition | — |
| `redacted_finding_count` | findings actually transformed | — |
| `suspected_finding_count` | findings with status `suspected`/`needs_review` | — |
| `provider_disagreement_count` | findings where ≥2 providers disagree on category | — |
| `uncertain_finding_rate` | suspected + disagreement | `finding_count` |
| `prevention_rate` | events meeting **all four** §6.5 conditions | actionable sensitive-data events |
| `provider_timeout_count` etc. | per provider, per outcome | — |

**Worked example** — one action, three findings, two redacted and one that caused
a block:

```
event_count                += 1
finding_count              += 3
blocked_event_count        += 1     (the action was blocked)
blocked_finding_count      += 3     (all 3 were in the blocked action)
redacted_event_count       += 0     (the action was blocked, not redacted)
redacted_finding_count     += 2     (2 were transformed before the block decision)
prevention_rate numerator  += 1     ONLY if NotForwarded evidence is present
```

`redacted_event_count = 0` alongside `redacted_finding_count = 2` is the
canonical illustration of why the two counters cannot be collapsed.

### 6.7 Storage tiers

| Tier | Contains | Retention | Who reads |
|---|---|---|---|
| tamper-evident audit (JSONL, hash-chained) | full fidelity incl. offsets | long | compliance export, forensics |
| queryable security events (durable) | event + finding rows, **no offsets** | medium | APIs, drill-down |
| metrics / time-series | bounded labels only | short-medium | alerting, SLOs |
| rollups | pre-aggregated dimensions | long | dashboard, reporting |

The lossy `audit_entry_to_storage_event` bridge should **not** be extended
field-by-field. It should be superseded by a dedicated sensitive-data projection
written alongside it, leaving the existing bridge untouched until the new
projection has a consumer — which also finally gives the durable tier a reader.

---

## 7. Architecture options

### Option 1 — Extend only the built-in Rust scanner

Cheapest, keeps everything in-process, no new trust boundary, works in WASM and
the SDK layer. But the coverage ceiling is real: no NER, no semantic
classification, and every recognizer is ours to maintain forever. §4.1 also shows
the existing heuristic layer is mis-calibrated for non-English input, so "just
extend it" starts from a defect.

**Rejected as the whole answer; adopted as the core of the answer.**

### Option 2 — Rust core plus optional local provider adapters ✅ **Recommended**

Deterministic Rust fast path always available and always authoritative for the
synchronous decision; a canonical, provider-neutral finding model; capability-based
routing; optional local adapters (custom protocol, Presidio, Gitleaks) consulted
asynchronously for large or high-risk payloads; Agent Assembly owns aggregation,
policy, approval and audit throughout.

Directly supported by the measurements: §3.3 shows transport cost is prohibitive
exactly where the fast path lives and negligible where deep inspection belongs.

### Option 3 — Replace the scanner with one external framework

**Disqualified by measurement.** Presidio is ~2 000× the fast path on the dominant
payload class, hard-fails above ~524 KB, has zero Chinese support with a
silent-clean failure mode, cannot run in the SDK or WASM layers, and adds 746 MiB
resident plus a Python runtime to a 6.8 MB image. It also inverts the trust model
the product is built on.

---

## 8. Migration

Six phases. The first two contain no provider at all.

| Phase | Content | Behavior change | Rollback |
|---|---|---|---|
| **0** | fix the CJK entropy defect + full-width digits; add CJK conformance vectors | **yes — a bug fix** | revert; vectors are new |
| **1** | canonical finding model wrapping the existing scanner, 1:1 with `CredentialKind` | **none** | type-only revert |
| **2** | provider port + in-tree test double; formalise the seam already hardcoded at `aa-gateway/src/engine/mod.rs:1438` | **none** (test double only) | remove trait impl |
| **3** | sensitive-data decision event + durable projection, written **alongside** the existing bridge | additive only | stop writing the projection |
| **4** | optional local adapters behind explicit config, default off, async deep path only | opt-in only | config flag |
| **5** | risk-based escalation, provider budgets, API/dashboard semantics | gated on shadow-mode agreement | feature flag |

**Compatibility invariants** that hold across every phase:

- `CredentialKind` variants and `as_str()` labels are frozen — they are pinned by
  26 conformance vectors and exposed by `/api/v1/scrub/patterns`.
- No committed golden vector is edited to make a change pass (ADR 0015).
- Redaction stays fail-closed.
- `RuntimeVerdict` stays the 5-way frozen enum (§6.3).

**Shadow mode** must segment by script, or the zh-TW false positives of §4.1 will
swamp the comparison signal until Phase 0 lands.

---

## 9. Proposed backlog

Proposed only — not created, per the ticket's instruction to wait for ADR and
product review.

| ID | Title | Depends on |
|---|---|---|
| `B-2` | 🐛 (aa-security): Stop classifying non-ASCII text as high-entropy secrets | — |
| `B-3` | 🐛 (aa-security): Normalise full-width digits before Luhn/SSN detection | — |
| `B-4` | 🐛 (aa-runtime): Preserve non-UTF-8 and chunk-split payloads on redaction write-back | — |
| `B-1` | ✨ (dashboard): Wire the Scrub surface to the shipped `/api/v1/scrub/*` routes | — |
| `B-5` | ✅ (conformance): Add CJK and full-width false-positive vectors | `B-2`, `B-3` |
| `B-6` | ✨ (aa-security): Canonical sensitive-data finding model over the existing scanner | ADR 0032 |
| `B-7` | ✨ (aa-security): `zh-TW` deterministic recognizer pack | `B-2`, `B-6` |
| `B-8` | ♻️ (aa-gateway): Formalise the detection seam at `engine/mod.rs:1438` behind the provider port | `B-6` |
| `B-9` | ✨ (aa-core): `SensitiveDataDecisionEvent` + finding records | ADR 0032, `B-6` |
| `B-10` | ✨ (aa-gateway): Durable sensitive-data projection alongside the audit bridge | `B-9` |
| `B-11` | ✨ (aa-proxy): Persist `ForwardedPayload::NotForwarded` as execution evidence | `B-9` |
| `B-12` | ✨ (aa-api): Sensitive-data analytics + drill-down endpoints | `B-10`, `B-11` |
| `B-13` | ✨ (aa-*): Local provider protocol + in-tree test double | ADR 0032, `B-6` |
| `B-14` | ✨ (aa-*): Presidio adapter, async deep path, opt-in | `B-13` |
| `B-15` | ✨ (aa-*): Gitleaks adapter with mandatory `--redact=100` | `B-13` |
| `B-16` | ✨ (dashboard): Sensitive-data analytics views | `B-12` |

```
B-2 ─┬─► B-5
B-3 ─┘        B-7 ◄── B-6 ◄── ADR 0032
              ▲        │
              │        ├─► B-8
              │        ├─► B-9 ─┬─► B-10 ─┬─► B-12 ──► B-16
              │        │        └─► B-11 ─┘
              │        └─► B-13 ─┬─► B-14
              │                  └─► B-15
B-1 (independent — correctness, ship now)
B-4 (independent)
```

---

## 10. Decisions required from Bryant

Only these three. Everything else in this report was derivable from code,
measurement or first-party sources, and none of these blocks further research.

### D-1 — Does "provider architecture" include out-of-process providers in v1?

**Why it can't be derived technically.** Both readings are defensible and the
answer determines the ADR's blast radius, not its content.

| | **A — in-process, in-tree adapters only (v1)** | **B — out-of-process providers in v1** |
|---|---|---|
| ADR impact | ADR 0032 `create`; nothing else moves | ADR 0032 plus explicit reconciliation with ADR 0002 / 0030 |
| Trust boundary | unchanged | new: a sensor process outside the trusted layer |
| Presidio/Gitleaks | not usable at all | usable, async only |
| Risk | low | moderate, and needs the UDS + peer-credential shape of §5.4 |

**Evidence**: §3.3 shows out-of-process is only economical for large payloads;
§3.4 shows Presidio is only viable asynchronously. So B buys exactly one thing —
third-party engines on the deep path — and A costs exactly that.

**Recommendation: A for v1, B behind a follow-up ADR.** Phases 0–3 of §8 contain
no provider at all and deliver most of the Epic's value (the zh-TW fix, the
canonical model, the event/analytics layer). Deferring B loses nothing on the
critical path and keeps three accepted ADRs untouched while the model settles.

**Consequence of delay**: none for Phases 0–3. Phase 4 cannot start.

### D-2 — How should the finer enforcement vocabulary relate to the frozen `RuntimeVerdict`?

**Why it can't be derived technically.** ADR 0018 deliberately froze five
variants and ADR 0024 says adding one is not additive on the wire. Choosing to
break that is a product call about contract stability.

- **A** — keep `RuntimeVerdict` frozen; carry `mask`/`tokenize`/`approval_*`/
  `shadow_only` in a **separate additive field** on the new event.
- **B** — extend `RuntimeVerdict`, accepting a breaking wire change and reopening
  ADR 0018 and 0024.

**Recommendation: A.** It costs one extra nullable field and preserves two
accepted ADRs plus every existing consumer. **Consequence of delay**: `B-9`
cannot be specified precisely, though the rest of Phase 3 can proceed.

### D-3 — Priority and release target for the zh-TW defect (§4.1)

**Why it can't be derived technically.** The fix is one line and technically
uncontroversial; *when* it ships is a release-risk and market call. `zh-TW` is the
product's home market, and today an agent speaking Chinese is denied outright
under `credential_action: Block`.

- **A** — hotfix into `v0.0.1-rc.7` ahead of everything in this Epic.
- **B** — normal Phase 0 sequencing within the Epic.

**Recommendation: A.** It is a one-line change to a leaf crate, it breaks no
conformance vector, and the current behavior is language-discriminatory in the
product's primary locale. **Consequence of delay**: `zh-TW` deployments cannot
use blocking mode, and their audit data stays unusable for the shadow-mode
comparison Phase 5 depends on.

---

## 11. Traceability

| Reference | Relation |
|---|---|
| [AAASM-5269](https://lightning-dust-mite.atlassian.net/browse/AAASM-5269) | this Spike |
| [AAASM-5270](https://lightning-dust-mite.atlassian.net/browse/AAASM-5270) | parent Epic |
| [AAASM-5174](https://lightning-dust-mite.atlassian.net/browse/AAASM-5174) | dispositioned in §2.7 — remains valid, split |
| [ADR 0032](../adr/0032-local-first-sensitive-data-provider-architecture.md) | the proposed decision |
| [ADR 0015](../adr/0015-dlp-trust-boundary-and-redaction-semantics.md) | parent decision; invariants preserved |
| [ADR 0018](../adr/0018-canonical-runtime-verdict-and-enriched-decision-record.md) | owns the verdict vocabulary; see §6.3 / D-2 |
| [ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md) | constrains provider form; see §5.4 |
| `aa-security/benches/spike_5269_payload_classes.rs` | reproduces §3.2 |
| `aa-security/benches/spike_5269_percentiles.rs` | reproduces §3.2 percentiles |
