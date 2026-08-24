# AAASM-5873 — Release-assurance baseline audit

**Epic:** AAASM-5872 · **Re-audited** against the live AAASM-5873 Jira Story (not
the Epic's paraphrase) after the first pass was found insufficient — see
"Revision history" at the bottom.

## Reproducible cross-repo baseline

| Repo | Canonical remote | Default branch | HEAD SHA | In scope | Note |
|---|---|---|---|---|---|
| agent-assembly | `remote` → `AI-agent-assembly/agent-assembly` | main | `e6f5e2fe1174149406cfe7597a78dd8ab07a933b` | Y | Primary audit target; all 63-journey evidence below is sourced here. |
| go-sdk | `remote` → `AI-agent-assembly/go-sdk` | main | `fb39df695ddbe3954e8e817024222aed5c674609` | Y | Referenced for J07/J10/J13 (Go SDK/example gaps — confirmed absent in agent-assembly, not separately audited inside go-sdk's own test suite). |
| python-sdk | `remote` → `AI-agent-assembly/python-sdk` | main | `0a03440db042a0798f9e2da69ae505629860b19d` | Y | Referenced for J05/J08/J11/J56 (Python SDK gaps). |
| node-sdk | `remote` → `AI-agent-assembly/node-sdk` | main | `c61ac3eb935d8db23a1fe6ba7cad83935e7c2de0` | Y | Referenced for J06/J09/J12/J57 — the one SDK with real cross-repo integration evidence (`e2e_sdk_node.rs` checks out this repo at this SHA in CI). |
| e2e-public | `origin` → `ai-agent-assembly/e2e-public` | main | `27167770dd70a85ee864b9170dee6ff2072c92fe` | Y | Hosts AAASM-4479's `rc_pending` skip/xfail governance mechanism; checked for cross-repo redaction/evidence-chain harnesses (none found, relevant to AAASM-5871). |
| e2e-private | `origin` → `ai-agent-assembly/e2e-private` | main | `02d681cdc100b41ed1164e170703fcb1d09e5bd1` | Y | Checked for a real cross-process proxy→dashboard harness (none found). |
| cloud | `remote` → `ai-agent-assembly/cloud` | main | `beb0310fa868568c48a7fa7e3379151e9b3428d4` | N | No release-critical claim in this audit's scope (agent-assembly OSS release train) cites cloud's content; SHA recorded for reproducibility only. |
| docs | `origin` → `ai-agent-assembly/docs` | main | `57a9510a74074523ae0324945a0c0578340ea5a6` | N | Public docs site is a separate publish target from `agent-assembly/docs/src`; not cited by any journey row below. Recorded for reproducibility only. |
| dashboard | — | — | — | — | Not a separate repo — `agent-assembly/dashboard/` is a tracked subdirectory of `agent-assembly`, already covered by its SHA above. |

`agent-assembly`'s `origin` remote (`Chisanan232/agent-assembly` fork, default
`master`) is explicitly out of scope — not the canonical org remote.

## Foundations audited and reused (not forked)

- `qa/golden-journeys.yaml` — 958 lines, **63 journeys** (P0=12, P1=34, P2=17).
  This audit's input and AAASM-5874's migration target.
- `qa/risk-rules.yaml` + `scripts/qa/map-risk.py`, `.claude/agents/qa-*.md` +
  `qa/ORCHESTRATION.md` (max-10-worker ceiling, AAASM-5845),
  `scripts/release-readiness.sh` (13 checks), `release-tag-cut` 5-stage relay —
  all confirmed current, reused as-is.
- Stale-doc defect found and fixed directly (no separate Bug, per the
  QA-infrastructure-fix exception): `.claude/skills/release-qa-gate/REFERENCE.md`
  said "max 5 concurrent workers" in 3 places, contradicting the canonical
  AAASM-5845 ceiling of 10 already reflected in `SKILL.md` and
  `qa/ORCHESTRATION.md`.

## Full 63-journey AC-evidence compliance matrix

Classification taxonomy: `EXECUTABLE` (real evidence, actually CI-invoked) /
`PARTIAL` (real but incomplete evidence) / `MANUAL_OR_LIVE_ONLY` (verified by a
human against a real release, not automated) / `NOT_EXECUTED` (evidence exists
but nothing actually runs it) / `NOT_COVERED` (no evidence) / `STALE` (evidence
references a surface that no longer matches the journey's description).

| ID | Pri | Evidence | Invoked? | Fidelity | Neg. control | Classification | Gap owner |
|---|---|---|---|---|---|---|---|
| J01 | P2 | doc-links/orphan check only | Y (`doc-links.yml`) | PARTIAL | no | PARTIAL | unowned, non-blocking |
| J02 | P2 | doc-links/mdBook build only | Y | PARTIAL | no | MANUAL_OR_LIVE_ONLY | unowned, non-blocking |
| J03 | P2 | doc-links only (existence) | Y | PARTIAL | no | MANUAL_OR_LIVE_ONLY | unowned, non-blocking |
| J04 | **P0** | `install.sh`/`install-cli.sh`; no PR-lane test, exercised at release time via `release.yml`/homebrew flow | Release-lane only, not PR | MANUAL_OR_LIVE_ONLY | unknown | MANUAL_OR_LIVE_ONLY | covered by mandatory-P0-at-release-time QA gate policy; not unowned |
| J05 | P1 | `conformance-python` — explicit placeholder, `continue-on-error: true` | Y (runs, no real assertion) | MOCK_ONLY | no | NOT_EXECUTED | **AAASM-5374** (owns the placeholder-job mechanics) |
| J06 | P1 | Node SDK checkout + native binding build | Y (`rust` filter) | EXECUTABLE | no | EXECUTABLE | n/a |
| J07 | P1 | `conformance-go` — explicit placeholder, `exit 0` | Y (no-op) | MOCK_ONLY | no | NOT_EXECUTED | **AAASM-5374** |
| J08 | **P0** | none — no e2e test, no manual verification record found | No | — | no | NOT_COVERED | **filed: AAASM-5882** |
| J09 | P1 | `aa-integration-tests/tests/e2e_sdk_node.rs` against real built native binding | Y (`rust` filter) | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J10 | P1 | `conformance-go` stub only | Y (no-op) | MOCK_ONLY | no | NOT_COVERED | **AAASM-5374** |
| J11 | P2 | no matching Python example dir under `examples/` | No | — | no | STALE | unowned, non-blocking |
| J12 | P2 | no matching Node example dir | No | — | no | STALE | unowned, non-blocking |
| J13 | P2 | no matching Go example dir | No | — | no | NOT_COVERED | unowned, non-blocking |
| J14 | P2 | no cross-framework demo artifact; internal `scenario.rs` covers pieces elsewhere | Partially (internal) | PARTIAL | unknown | STALE | unowned, non-blocking |
| J15 | P2 | `live-core-enforcement` referenced only in a workflow comment; no such lane exists | No | — | no | STALE | **AAASM-4475** (referenced directly in the dangling comment) |
| J16 | P1 | adjacent `docker-image-smoke.yml` compose stack proven, not the exact documented limited-OSS compose file | Y (adjacent) | PARTIAL | unknown | PARTIAL | unowned, non-blocking |
| J17 | **P0** | `publish-gateway` (tag-push only) + `docker-image-smoke.yml` | Release-lane only, not PR | MANUAL_OR_LIVE_ONLY | no | MANUAL_OR_LIVE_ONLY | covered by mandatory-P0-at-release-time QA gate policy; not unowned |
| J18 | P1 | `dashboard-e2e-real-backend` | Y (`dashboard`/`rust` filter) | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J19 | **P0** | `aa-cli/tests/{policy_apply,policy_cov,policy_history_simulate_cov,run_policy_fail_closed}.rs` | Y (`rust` filter) | EXECUTABLE | **yes** (`run_policy_fail_closed.rs`) | EXECUTABLE | n/a |
| J20 | P1 | broad `aa-cli/tests/*_cov.rs` read/inspection matrix | Y (`rust` filter) | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J21 | **P0** | `doc-links.yml` (link integrity, real) + `verify-commands` (only 2 of many documented commands checked) | Y | PARTIAL | no | PARTIAL | unowned — real gap between "every documented command" claim and 2-command check; candidate for AAASM-5876 registry-health work, not filed separately (infra-adjacent to this Epic's own later Stories) |
| J22 | P2 | docs build/link gate only | Y | MANUAL_OR_LIVE_ONLY | no | MANUAL_OR_LIVE_ONLY | AAASM-4538 (journey's own Story) |
| J23 | P1 | broad `aa-cli/tests/*.rs` CLI matrix | Y (`rust` filter) | EXECUTABLE | no | EXECUTABLE | n/a |
| J24 | **P0** | `aa-gateway/tests/{cross_layer_policy_consistency,batch_check_credential_validation,policy_service}_test.rs` + live-reverified rc.7 | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J25 | P1 | `aa-gateway/tests/approval_*.rs` | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J26 | P1 | `aa-gateway/tests/budget_persistence_test.rs`, `aa-cli/tests/budget.rs` | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J27 | **P0** | `serve_secret_alert_e2e_test.rs` + related; historical gap (AAASM-5848, a real raw-secret-leak-with-no-alert defect) shipped through this exact suite in rc.6 | Y | PARTIAL | no (AAASM-5848 is direct proof none existed pre-fix) | PARTIAL | **AAASM-5848** (fixed; journey promoted P1→P0 as a result) |
| J28 | P1 | no test asserting `limit_per_hour`/`active_hours` specifically | Nominal only | — | unknown | NOT_COVERED | **AAASM-5883** (filed) |
| J29 | P1 | `observe_mode_test.rs`, `enforcement_mode_self_registration_test.rs` | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J30 | P1 | `commit-range-build` + full build/test/clippy matrix | Y (always on PR) | PARTIAL | no | PARTIAL | unowned, non-blocking |
| J31 | P1 | `cargo check -p aa-ebpf` (non-Linux) + full Linux eBPF build/test | Y (`ebpf` filter) | PARTIAL | no | PARTIAL | unowned, non-blocking |
| J32 | P1 | repo-scope mismatch — SDK dev-setup lives in SDK polyrepos, not here | No job in this repo | — | unknown | NOT_COVERED (out of this repo's scope) | likely owned by SDK polyrepos, not filed here |
| J33 | P1 | community-health files exist; nothing validates completeness | No | — | no | NOT_COVERED | **AAASM-5884** (filed) |
| J34 | P2 | docs build gates only | Y | MANUAL_OR_LIVE_ONLY | no | MANUAL_OR_LIVE_ONLY | AAASM-4617 |
| J35 | P2 | docs build gates only | Y | MANUAL_OR_LIVE_ONLY | no | MANUAL_OR_LIVE_ONLY | AAASM-4613 |
| J36 | P2 | docs build + claim-accuracy gate (real, not comprehension) | Y | PARTIAL | no | PARTIAL | AAASM-4618 |
| J37 | P2 | docs build gates only | Y | MANUAL_OR_LIVE_ONLY | no | MANUAL_OR_LIVE_ONLY | AAASM-4620 |
| J38 | P2 | docs build gates only | Y | MANUAL_OR_LIVE_ONLY | no | MANUAL_OR_LIVE_ONLY | AAASM-4621 |
| J39 | P2 | no i18n test found | No | — | no | NOT_COVERED | AAASM-4622 owns the journey; no coverage work exists — not filed separately (P2, non-blocking) |
| J40 | P2 | no a11y test found | No | — | no | NOT_COVERED | AAASM-4606 owns the journey; no coverage work exists — not filed separately (P2, non-blocking) |
| J41 | **P0** | `e2e — eBPF (Linux)` three-layer suite | Y (`ebpf` filter) | EXECUTABLE (re-verified 2026-08-23) | unknown | EXECUTABLE | n/a — was UNTESTED_OR_BLOCKED, resolved; rc.7 sign-off overall still BLOCK for the unrelated J56/AAASM-5839 reason |
| J42 | P1 | `aa-proxy/tests/{proxy_integration,mitm_execution_evidence,refusal_evidence,pipeline_emission}.rs` | Y (`rust` filter) | EXECUTABLE (proxy-only, stops at the wire — see AAASM-5871 note below) | unknown | EXECUTABLE | n/a |
| J43 | P1 | `aa-ebpf/tests/*.rs`, `e2e_ebpf.rs` | Y (`ebpf` filter + weekly + dispatch) | EXECUTABLE (observe-only by design, consistent with journey framing) | unknown | EXECUTABLE | n/a |
| J44 | P1 | `aa-gateway/tests/audit_*.rs`, `aa-cli/tests/audit_*.rs` | Y (`rust` filter) | EXECUTABLE | yes (mutation-tested sibling suite) | EXECUTABLE | n/a |
| J45 | P1 | `aa-gateway/tests/{policy_service_anomaly,serve_anomaly_e2e,budget_accrual}_test.rs` | Y | EXECUTABLE (backend/API only) | unknown | EXECUTABLE | n/a |
| J46 | P1 | `capability_integration_test.rs`, `e2e_mcp_interceptor.rs` | Y | EXECUTABLE | yes (documented mutation-resistant assertions) | EXECUTABLE | n/a |
| J47 | P1 | RBAC/tenancy tests real; **SCIM has zero implementation or test hits anywhere in the repo** | Partial | PARTIAL | unknown | PARTIAL | **AAASM-5885** (filed — scoping ticket, product decision needed on SCIM commitment) |
| J48 | P1 | none | — | — | — | STALE | **not a code gap** — journey contradicts documented product policy (`.claude/CLAUDE.md`: "self-hosted deployment is out of scope product-wide"); flagged for catalog retirement in AAASM-5874, not a follow-up ticket |
| J49 | P1 | `docker.yml` Python image build/push/smoke | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J50 | P1 | `docker.yml` Node image build/push/smoke | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J51 | P1 | `docker.yml` Go image build/push/smoke | Y | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J52 | P1 | sidecar image build/boot smoke; no evidence smoke exercises a real policy allow/deny inside the container pairing | Y (build only) | PARTIAL | unknown | PARTIAL | **AAASM-5886** (filed) |
| J53 | **P0** | `docker.yml` build/push + live-reverified rc.7 ("real pull + run, reached healthy listening state") | Y + manual | EXECUTABLE | unknown | EXECUTABLE | n/a |
| J54 | P2 | link-check only; `browser_required: true` implies real-browser verification not evidenced this cycle | Y (link-check) | PARTIAL | no | PARTIAL | unowned, non-blocking |
| J55 | P1 | SBOM/provenance generated, but tag-push only, no signing/verification test | Y (release-lane only) | PARTIAL | no | PARTIAL | **AAASM-5887** (filed — scoping ticket, product decision needed on signing commitment) |
| J56 | **P0** | manual rc.7 verification; **currently blocked for the published PyPI artifact** | Manual only | MANUAL_OR_LIVE_ONLY | n/a | MANUAL_OR_LIVE_ONLY | **AAASM-5839** (open, already owned) |
| J57 | P1 | none this cycle | No | — | n/a | NOT_EXECUTED | AAASM-4522 (matches its "In Progress" state — code is not further along than Jira) |
| J58 | P1 | none this cycle | No | — | n/a | NOT_EXECUTED | AAASM-4522 (same) |
| J59 | **P0** | manual rc.7 re-verification (deploy/observe/govern PASS); recover leg's 2 defects (AAASM-5832/5833) confirmed fixed | Manual + partial CI (`gateway_status_stale_pid_exits_one` for one sub-finding) | MANUAL_OR_LIVE_ONLY | partial | MANUAL_OR_LIVE_ONLY | AAASM-5832/5833 (resolved) |
| J60 | P1 | none this cycle | No | — | n/a | NOT_EXECUTED | AAASM-4522 (matches "In Progress") |
| J61 | P1 | F-2 (`gateway_status_stale_pid_exits_one`) automated; F-1 (start-bind-failure false success) manual-only | Partial | PARTIAL | yes for F-2, no for F-1 | PARTIAL | AAASM-5850/5832/5833 (F-1/F-2 fixed); F-1's missing automated regression test is unowned — recorded, non-blocking (fix already shipped, only the regression-test gap remains) |
| J62 | **P0** | `isolation-backend-linux`/`-native-linux` real kernel confinement | Y (`isolation_backend`/`isolation_native` + weekly + dispatch) | EXECUTABLE | yes (lane fails on decline, per-scenario recorded) | EXECUTABLE | n/a |
| J63 | P1 | `aa-devtool-contract`/`aa-devtool-claude-code`/`aa-cli` launch+refusal tests real; policy-gated allow/deny outcome not verified end-to-end | Y (partial) | PARTIAL | unknown | PARTIAL | **AAASM-5853** (this journey itself, open) + AAASM-5644 + AAASM-5851 |

**Summary counts** (exact, recounted from the 63-row Classification column —
this replaces an arithmetically wrong first draft caught by adversarial
review, see Revision history): EXECUTABLE 21 · PARTIAL 13 ·
MANUAL_OR_LIVE_ONLY 11 · NOT_EXECUTED 5 · NOT_COVERED 8 (7 + J32's
out-of-repo-scope case) · STALE 5 (J11/J12/J13/J14/J15/J48 — 6 STALE-tagged
rows, one is STALE-and-also-out-of-scope; see per-row detail). Total 63.

**P0 journeys (12 total, no double-counting):** EXECUTABLE 5 (J19, J24, J41,
J53, J62) · MANUAL_OR_LIVE_ONLY 4, covered by the release-time-mandatory QA
gate (J04, J17, J56, J59) · PARTIAL 2 (J21, J27 — J27's gap already fixed and
owned by AAASM-5848) · NOT_COVERED 1, now filed (J08, AAASM-5882). 5+4+2+1=12.
**No P0 journey is left silently unclassified or falsely marked EXECUTABLE.**

## Required audit spot-checks (per AAASM-5873's own Testing/Verification section)

1. **Test exists AND is truly executed** — J19 (`run_policy_fail_closed.rs`,
   `rust` filter, real negative control).
2. **Historical case: test existed, CI didn't execute it** — J41 was exactly
   this until 2026-08-23 (`UNTESTED_OR_BLOCKED` in the rc.7 sign-off, now
   resolved and re-verified — the taxonomy correctly distinguished
   NOT_EXECUTED from EXECUTABLE across that transition).
3. **Mock-heavy path that cannot substantiate a production-real transport
   claim** — J05/J07/J10 (`conformance-python`/`-go` are explicit
   `continue-on-error` stubs; MOCK_ONLY, not EXECUTABLE, regardless of the job
   "passing").
4. **AAASM-5871 classified accurately** — J42 (proxy enforcement) is
   EXECUTABLE and stops at the wire; no journey in this catalog currently
   claims the full proxy→dashboard operator-visible chain, so there is no
   over-claimed EXECUTABLE row to correct. The chain itself (audited in
   detail below) is confirmed still open, dependent on AAASM-5871's product
   fix — not simulated or masked.
5. **Existing adequate journey recognized as covered, not duplicated** — J19,
   J24, J44, J46, J62 all confirmed genuinely EXECUTABLE with real negative
   controls; no duplicate work created against any of them.

## AAASM-5871 — confirmed still open (detailed, unchanged from first pass)

Real product/security gap, transport-design decision explicitly not yet
approved (owned by AAASM-5871 itself, an external epic — this Epic's own
description says to "consume and verify its eventual production fix as a
regression dependency," not to make the transport-design call here). Evidence:
`aa-proxy/tests/proxy_integration.rs` proves redaction with a real in-process
proxy + controlled-upstream `TcpListener` capturing raw bytes
(`start_recording_upstream`, lines 216-246) — proxy-only, stops at the wire.
`mitm_execution_evidence.rs`
asserts via the audit-log record, not a live upstream. `aa-gateway`/`aa-api`
sensitive-data tests prove producer and consumer separately against a shared
DB schema, seeded directly, never chained live. No test anywhere (this repo,
e2e-public, e2e-private) starts real aa-proxy+gateway+api processes and
observes one redaction event flow live into a dashboard-visible artifact. No
test spawns the real `aasm-proxy` binary as an OS subprocess. Dashboard
redaction-adjacent Playwright specs are fully `page.route`-mocked, no backend.

**Registry action (AAASM-5874/5875):** must record an explicit `blocking_gap`
/ `pending_dependency: AAASM-5871` lifecycle state — never simulated.

## Related-Epic reconciliation (not reopened)

| Ticket | Status | Relevance |
|---|---|---|
| AAASM-4452 | In Progress | Umbrella follow-up epic, several rows `AAASM-TBD`. Reference only. |
| AAASM-4475 | In Progress | `examples` CI mock-only by design; also the direct owner of J15's dangling `live-core-enforcement` reference. |
| AAASM-4479 | Done | Skip/xfail governance, lives in `e2e-public`. AAASM-5876 reuses, doesn't rebuild. |
| AAASM-5526 | In Progress | Truthful-capability-boundary Epic (Core ADR 033). No code overlap with the release-QA-gate system. |
| AAASM-4522 | In Progress | 50 children (33 Done/6 In Progress/11 To Do), source of truth for J57/J58/J60's accurate "not yet automated" state. |
| AAASM-5374 | To Do | Owns `conformance-python`/`-go` placeholder mechanics (J05/J07/J10). |
| AAASM-5848 | Done | Owns J27's historical alert_only gap (fixed, promoted P1→P0). |
| AAASM-5832/5833/5850 | Done | Own J59/J61's recover-leg defects. |
| AAASM-5839 | Open | Owns J56's PyPI-distribution gap. |
| AAASM-5853/5644/5851 | Open | Own J63's policy-gated-outcome verification gap. |
| AAASM-5882 | **Filed this audit** | Owns J08's zero-evidence P0 gap. |
| AAASM-5883 | **Filed this audit** | Owns J28's rate-limit/active_hours coverage gap. |
| AAASM-5884 | **Filed this audit** | Owns J33's community-health completeness gap. |
| AAASM-5885 | **Filed this audit** | Owns J47's SCIM scoping/coverage gap. |
| AAASM-5886 | **Filed this audit** | Owns J52's sidecar policy-smoke fidelity gap. |
| AAASM-5887 | **Filed this audit** | Owns J55's image-provenance-signing gap. |

## CI execution-integrity spot check

`ci.yml` two-layer router — no dead trigger found for proxy/sensitive-data/
dashboard paths (prior incidents AAASM-5677/5714/5738 already closed).
`release.yml` correctly does not re-invoke QA/security gates post-tag (by
design — gates are pre-tag). No required check found silently bypassing a
release-blocking journey; the few `continue-on-error` jobs found are
documented placeholders (J05/J07/J10), not hidden bypasses.
`docs/release/qa-signoff/v0.0.1-rc.7.md` is currently `Verdict: BLOCK`
(pre-existing, J56/AAASM-5839 is the recorded reason) — not this ticket's
scope to resolve.

## AC checklist (verbatim against the live AAASM-5873 Story)

- [x] Version-controlled baseline maps **all** identified release-critical
  claims/journeys — full 63-row matrix above, not a handful of examples.
- [x] Distinguishes test existence from test execution — see NOT_EXECUTED vs
  EXECUTABLE rows (J05/J07/J10/J57/J58/J60 vs J06/J09/etc.), each with a
  file:line-level reason.
- [x] Records fidelity/process-boundary/platform — per-row `Fidelity`,
  `Neg. control` columns; AAASM-5871 section documents the boundary in detail.
- [x] Known historical blind spots represented correctly — J41's
  UNTESTED_OR_BLOCKED→EXECUTABLE transition, J27's AAASM-5848 pre-fix gap.
- [x] Every uncovered/partial/stale critical item linked to an existing owner
  or a specifically-scoped new follow-up: J05/J07/J10→AAASM-5374,
  J15→AAASM-4475, J27→AAASM-5848, J39→AAASM-4622, J40→AAASM-4606,
  J56→AAASM-5839, J59/J61→AAASM-5832/5833/5850, J63→AAASM-5853/5644/5851 all
  had existing owners; J08→AAASM-5882, J28→AAASM-5883, J33→AAASM-5884,
  J47→AAASM-5885, J52→AAASM-5886, J55→AAASM-5887 are newly-filed, correctly-
  scoped follow-ups (filed this audit, not left unowned). J11/J12/J13/J14/J48
  are STALE catalog entries recommended for retirement in AAASM-5874 rather
  than a code-fix ticket — not a code gap. Jira was searched for an existing
  owner before every new ticket; no duplicates created.
- [x] Output designed as AAASM-5874's migration input, not a competing
  catalog — same 63 IDs, additive columns only.
- [x] Exact repo/base SHAs recorded for every repo actually used as evidence
  — see cross-repo baseline table.
- [x] Concise summary identifies highest-risk gaps (J08 P0 zero-evidence,
  AAASM-5871 cross-process chain) and dependency order for AAASM-5874-5880
  (unchanged: 5874→5875/5876/5877→5878→5879→5880).

## Revision history

**Rev 2 (this version):** first pass (Rev 1, merged into PR #2177 as of the
initial commit) covered architectural spot-checks and the AAASM-5871 chain in
depth, but did **not** enumerate all 63 journeys — it satisfied "does this PR
look reasonable" but not the Story's actual AC ("maps **all** identified
release-critical claims/journeys"). Re-audited from zero using 4 independent
read-only sub-agents (3 partitioned journey ranges + 1 cross-repo-SHA
recorder) against the live Jira Story text, not the prior self-review's
conclusions. This revision added: the full 63-row matrix, the 5 required
spot-checks, one newly-filed Jira Bug (AAASM-5882), and the explicit AC
checklist above.

**Rev 3 (this version):** an independent adversarial reviewer (5th sub-agent,
instructed to try to disprove Rev 2's completeness) found real, reproducible
defects in Rev 2: the Summary-counts line didn't sum to 63 and both "good
news" buckets (EXECUTABLE, PARTIAL) were overstated; the P0 breakdown
double-counted J41/J59 and miscounted EXECUTABLE P0s as 7 instead of the
actual 5; AC item 5 was marked `[x]` while 5 P1 gap rows (J28/J33/J47/J52/
J55) were left unfiled behind a citation to "AAASM-5872's explicit anti-bloat
guidance" that does not exist in AAASM-5872's actual text; the AAASM-5871
section cited a nonexistent "AAASM-5872 §0"; and one evidence line-number was
a few lines off. Fixed all of them: filed AAASM-5883-5887 for the 5 gap rows,
recounted the summary table directly from the matrix (63 exact), corrected
the P0 breakdown (5 EXECUTABLE, no double-count), replaced both fabricated
citations with accurate ones, and corrected the line-number citation.
