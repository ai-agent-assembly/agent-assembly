# `qa/golden-journeys.yaml` — machine-readable journey catalog

Selection/index layer over [AAASM-4522](https://lightning-dust-mite.atlassian.net/browse/AAASM-4522),
which remains the durable human-readable requirement source. This file exists
so `/release-qa-gate` (AAASM-5821) and the risk mapper (AAASM-5829) can select
journeys deterministically from changed surfaces without re-reading 60 Jira
Stories every release.

**Do not copy Jira description prose into this file.** Each row is a thin
index: stable ID, Jira reference, priority (per
[the release QA policy](../docs/src/qa/release-qa-policy.md)'s P0/P1/P2
definitions), persona/track, affected surfaces (path prefixes, not exact
files), entry point, verification lanes, browser requirement, and a one-line
pointer back to the Jira Story for the actual acceptance contract.

## Fields

| Field | Meaning |
|---|---|
| `id` | Stable ID (`J01`-`J60`), matches the `[Journey NN ...]` numbering already used in AAASM-4522 Story titles — survives title wording changes. |
| `jira` | The AAASM-4522 child Story key. |
| `name` | Concise name (not the full Story description). |
| `priority` | `P0` \| `P1` \| `P2`, per the release QA policy. |
| `persona_track` | The journey's category/persona (Discovery, Install, Policy, Function, Golden Path, ...). |
| `surfaces` | Path prefixes this journey's outcome depends on — used for risk-mapper selection. |
| `entry_point` | How a user reaches this journey (`cli`, `sdk`, `docs`, `dashboard`, `gateway`, `container`, ...). |
| `lanes` | Which evidence-contract lane(s) (AAASM-5828) this journey exercises. |
| `browser_required` | Whether real-browser verification is needed (per this repo's user-smoke convention — no `page.route`/mocked substitutes). |
| `outcome` | One line pointing back to the Jira Story for the real acceptance contract — never a copy of it. |

## The P0 set (12 journeys — within AAASM-5820's 8-15 bound)

`J04` (install CLI), `J08` (Python SDK Quick Start), `J17` (gateway from
published artifact), `J19` (author/apply policy), `J21` (doc/command
integrity), `J24` (allow/deny enforcement), `J27` (data protection —
promoted P1→P0 by AAASM-5848 after a real alert_only defect shipped
undetected), `J41` (three-layer interception model), `J53` (gateway
container image), `J56` (Golden Path — Python Dev), `J59` (Golden Path —
Operator), `J62` (`aasm run` execution-isolation confinement). Covers
primary install, primary SDK smoke, gateway startup, policy authoring +
enforcement, sensitive-data protection, core architecture, primary
deployment, docs integrity, isolation confinement, and one golden-journey
walkthrough per major entry point (CLI/SDK, container, operator).

<!-- 2026-08: this section previously listed 10 journeys and omitted J27/J62,
which had been added to the catalog's actual P0 set without a corresponding
doc update — found and fixed during AAASM-5874. -->

## Release Assurance Registry fields (AAASM-5874)

Additive, all optional except where noted — evolves this same file into the
executable claim→evidence registry rather than forking a second catalog.

| Field | Meaning |
|---|---|
| `release_blocking` | `true` if this journey must have current evidence for every release, independent of `priority` (an escalated P1 can be marked `release_blocking` without renumbering it). |
| `lifecycle_state` | Truthful coverage state: `automated` \| `partial` \| `manual_live` \| `unsupported` \| `gap` \| `stale` \| `retired`. Required when `release_blocking: true`. |
| `evidence` | List of `{repo, kind, selector}`; `kind` is `test` \| `ci_job` \| `manual_record`. Required (non-empty, resolvable) when `lifecycle_state: automated` and `release_blocking: true`. |
| `execution_lanes` | `pr` \| `main` \| `nightly` \| `release` \| `live_dogfood`. Required when `lifecycle_state: automated` and `release_blocking: true`. |
| `fidelity` | `mock` \| `controlled_fake` \| `real_local_process` \| `container` \| `published_artifact` \| `real_external_provider`. Required alongside `execution_lanes`. |
| `platforms` | Required OS/runner scope, when relevant. |
| `negative_control` | Reference to the mutation/fault-injection evidence proving this journey's test is load-bearing. |
| `gap_owner` | An `AAASM-*` ticket owning an incomplete/missing entry. Required when `release_blocking: true` and `lifecycle_state` is `partial`/`gap`/`unsupported`/`stale`. |
| `retirement` | `{reason, ref}` — used only for `lifecycle_state: retired`. The row is never deleted (AC3: stable IDs survive); a retired entry is excluded from active selection instead. |

### How the registry stays current

- **New/changed release-critical claim** → add or update the journey row
  (new `id` if it's a genuinely new guarantee, updated `evidence`/
  `lifecycle_state` if an existing guarantee's implementation changed) as
  part of the same PR that changes the behavior — the same discipline
  AAASM-5844's feature→coverage reconciliation already applies via
  `feature_refs`.
- **A deterministic defect found by QA/dogfood** → map it to the journey it
  falls under (`gap_owner` already points at the owning Bug) rather than
  inventing a new row; if no journey covers the guarantee that broke, that
  itself is the gap — file/extend a journey for it.
- **Test implementation renamed/refactored** → update only `evidence[].
  selector`. The stable `id` never changes, so a rename does not silently
  drop the guarantee's identity (validated by
  `scripts/qa/validate-golden-journeys-negative-control.sh` case 7).
- **Coverage that can't currently be automated** → represent honestly as
  `lifecycle_state: manual_live` (intentional) or `gap` (should exist, does
  not yet, has an owner) — never omit the field or claim `automated`
  without resolvable `evidence`.
- **Incremental reconciliation** (every release after the AAASM-5873
  baseline) uses this registry + the feature delta, not a full re-audit —
  see `.claude/skills/release-qa-gate/REFERENCE.md`.

## Validation

```bash
python3 scripts/qa/validate-golden-journeys.py qa/golden-journeys.yaml
```

Catches duplicate `id`/`jira` values, invalid `priority`, missing required
fields, a P0 set outside the 8-15 bound, and (AAASM-5874) any
`release_blocking` entry with missing/invalid `lifecycle_state`, an
`automated` entry with missing/unresolvable `evidence` or invalid
`execution_lanes`/`fidelity`, or a `partial`/`gap`/`unsupported`/`stale`
entry missing `gap_owner`. `evidence[].selector` for `kind: test` is resolved
by file-existence + name grep against this checkout — it does not invoke a
build/test runner.

**AAASM-5876 (CI-execution integrity)** additionally catches, for a `test`-
kind evidence entry on a `release_blocking` + `automated` journey:

- the evidence file's path is not covered by **any** `ci.yml`
  `on.push.paths` trigger glob — a real dead trigger (Core ADR 028): a
  release-blocking claim can point at a real test file that no workflow on
  `main` actually runs. This is the exact "tests exist but CI never
  executes them" failure mode that motivated this Story (a real Dashboard
  Playwright suite once existed with no invoking workflow).
- the referenced test is marked `#[ignore]` — a deterministic skip is never
  automated evidence. Reclassify honestly as `lifecycle_state: gap` with a
  `gap_owner` instead of leaving it `automated`; this reuses AAASM-5874's
  existing `gap_owner` mechanism rather than inventing a second waiver
  system (AAASM-4479's precedent — this repo's tests are Rust/nextest, not
  pytest, so the `rc_pending` marker in `e2e-public` doesn't apply here;
  `#[ignore]` is this repo's actual skip primitive).
- a declared `platforms` entry has no matching `runs-on:` in `ci.yml` —
  required coverage with literally no execution path (e.g. `windows` when
  every job in `ci.yml` currently runs on `ubuntu-latest`).

This is a **static** check (parses `ci.yml`'s glob list and greps for
`#[ignore]`/`runs-on:`) — it does not reconcile actual per-run JUnit/nextest output
against journey IDs for the exact candidate SHA. That reconciliation is
AAASM-5878's scope (binding evidence to the exact release candidate), not
this validator's.

**When adding/changing/removing a journey**, to avoid registry/workflow
drift: if the evidence file's directory isn't already covered by an
existing `ci.yml` filter, add both the `on.push.paths` entry and the
`dorny/paths-filter` glob in the same PR (Core ADR 028) — the validator will
catch a missed one for any `automated` + `release_blocking` entry, but P1/P2
entries aren't strictly checked, so don't rely on the gate alone for those.

Negative-control proof this is load-bearing (16 fixtures, exit-code
assertions, mirrors `scripts/tests/release-readiness-qa-negative-control.sh`):

```bash
bash scripts/qa/validate-golden-journeys-negative-control.sh
```

## Negative controls (AAASM-5877)

A `release_blocking` + `automated` journey on the `security` lane must
declare a non-empty `negative_control` — enforced by the validator (see
`docs/src/qa/release-qa-policy.md`'s "Negative-control policy"). This is
what's actually declared today, spanning the 3 required classes from
AAASM-5877's own scope:

| Class | Journey | Negative control | What it proves |
|---|---|---|---|
| Security enforcement | `J24` (allow/deny) | `cross_layer_policy_consistency_test.rs::policy_without_the_guard_clause_produces_no_deny` | Asserts the `/etc` deny is genuinely absent when the policy document omits the guard clause (the sibling test `artificial_divergence_is_detected` asserts the presence half, for the document that has the clause) — together, a real differential through the same real `lower_to_ebpf`, proving the lowering genuinely derives denies from policy input, not a hardcoded emit. |
| Security enforcement | `J41` (three-layer interception) | `e2e_ebpf.rs::ebpf_catches_traffic_that_bypasses_proxy` | Simulates the SDK/proxy layers being absent and asserts eBPF independently observes the traffic they'd otherwise catch — proves the "three layers, each independently authoritative" claim isn't just three tests of the same path. |
| Cross-process evidence/observability | `J27` (data protection) | `sensitive_data_producer_test.rs::primary_a_write_failure_leaves_the_decision_intact_and_is_counted` | Genuine fault injection via a `FailingStore`: asserts the lost projection row is actually counted (`written=0`, `write_failures=1`) while the enforcement decision itself stays unaffected — proves a sensitive-data projection-write failure is observable, not silently dropped. |
| Registry/CI execution-integrity | (the registry-health gate itself) | `scripts/qa/validate-golden-journeys-negative-control.sh` cases 9-13 (AAASM-5876) | Removes/breaks a required execution path (dead trigger, `#[ignore]`d evidence, unsupported platform) in an isolated fixture and asserts the gate goes non-zero — this Story's own required demonstration that "tests exist but nothing runs them" is caught, not silently green. |

All four selectors are pre-existing or newly-written real tests, but three of
the four went through a round of independent adversarial review finding they
didn't actually prove what they claimed, and had to be repointed:

- `J24`'s first candidate (`artificial_divergence_is_detected`) and `J44`'s
  original candidate (`audit_seq_recovery_test.rs::without_recovery_seq_would_duplicate`)
  were both tautological — each simulated the broken state by mutating a
  local copy of the test's own data rather than re-invoking the real
  production function with genuinely broken input, so neither actually
  proved the property it claimed to. `J24` was repointed to a newly-written,
  genuinely differential test in the same file; `J44`'s claim was removed
  rather than left standing on disproven evidence.
- `J27`'s first candidate (`primary_seam_writes_the_event_and_its_finding_rows`,
  proposed as `J44`'s replacement for the "cross-process evidence" class) was
  a second, independent round's finding: it's the test file's own
  self-labeled **positive** control (its docstring says so directly) —
  real code, no fault injected, happy path only. A negative control has to
  exercise a genuinely broken state and assert the non-pass outcome, not
  merely call a real function. Repointed to
  `primary_a_write_failure_leaves_the_decision_intact_and_is_counted`, which
  injects a real fault (a `FailingStore`) and asserts the resulting lost row
  is actually counted rather than silently dropped.

`J41`'s evidence
selector (`aa-integration-tests/tests/e2e_ebpf.rs`) also had a real CI dead-
trigger gap — `ci.yml`'s `ebpf` path filter only matched `aa-ebpf*/**`, so a
change to that test file alone would not retrigger `e2e-ebpf-linux` on PR
(schedule/`workflow_dispatch` only); fixed by adding the file to the filter
in the same PR (AAASM-5877), per this doc's own dead-trigger policy above.
None of the surviving controls weaken production/default state: each
mutates a local, in-test copy of data or process topology, asserts on it,
and the process exits — nothing persists outside the test's own process.

## Selection demonstration

```bash
python3 scripts/qa/select-journeys-demo.py aa-gateway/src/policy
```

Given a changed-surface list, prints the P0 set plus every P1/P2 journey whose
`surfaces` prefix-matches — without reading any Jira Story. This script is a
demonstration of selectability, not the real risk mapper; AAASM-5829 owns the
production mapping logic (which also assigns/refines `risk_tier`, which this
catalog does not carry — risk is per-surface, not per-journey).
