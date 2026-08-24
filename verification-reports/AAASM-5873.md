# AAASM-5873 — Release-assurance baseline audit

**Epic:** AAASM-5872 · **Baseline SHA:** `c1e2c2ae9fdff6c1cfd593a3137b89ec538fd291` (`remote/main`)
**Scope:** one-time cross-repo audit mapping release-critical claims to actual
executable evidence, per AAASM-5872 §2. Does not re-litigate AAASM-5819/5842
(both Done, reused as-is) or duplicate open work already owned by other Epics.

## 1. Existing foundations (confirmed current, reused as-is)

- `qa/golden-journeys.yaml` — 958 lines, **63 journeys** (P0=12, P1=34, P2=17).
  Schema: `id`, `jira`, `name`, `priority`, `persona_track`, `surfaces`,
  `entry_point`, `lanes`, `browser_required`, `outcome`, optional `feature_refs`.
  This is the registry AAASM-5874 evolves — not forked.
- `qa/risk-rules.yaml` + `scripts/qa/map-risk.py` — deterministic changed-path
  → risk/lane/journey mapping; union-of-matches, highest-risk-wins, MEDIUM
  fallback (never LOW). Sound, reused as-is.
- `.claude/agents/qa-*.md` (5 roles) + `qa/ORCHESTRATION.md` — max-10-worker
  ceiling (AAASM-5845), no nested spawning. Reused as-is.
- `scripts/release-readiness.sh` — 13 checks; checks 11/12 independently gate
  on `Verdict: PASS` in the committed security/QA sign-offs. Reused as-is.
- `release-tag-cut` skill — 5-stage relay (security-gate + qa-gate → tag-cut
  → `release.yml` fan-out → channel-validate → homebrew-tap-merge). Reused as-is.
- `release.yml` does **not** re-invoke the QA/security gates post-tag — this
  is correct by design (both gates are stage-0, pre-tag; `release.yml` only
  runs after a tag already implies they passed), not a gap.

## 2. Defect found and fixed in this ticket (ordinary, fixed directly)

`.claude/skills/release-qa-gate/REFERENCE.md` (lines 281, 287, 375) still said
**"Maximum 5 concurrent workers"** / "2 of 5 slots, 3 free", contradicting the
canonical AAASM-5845 ceiling of **10** already reflected in `SKILL.md`'s
frontmatter description and `qa/ORCHESTRATION.md`. Stale detail page, no
behavioral effect (nothing enforces the wrong number programmatically), but a
false statement about the gate's own governance. Fixed in this PR (doc-only,
no new Jira Bug per the QA-infrastructure-fix exception in
`FINDING-VERIFICATION-PROTOCOL.md`).

## 3. Confirmed open gap this Epic must not mask: AAASM-5871

Real product/security gap, **still open in current code**, transport-design
decision explicitly not yet approved (per AAASM-5871 itself — out of this
Epic's decision authority, see AAASM-5872 §0 "consume and verify... as a
regression dependency").

Evidence (current `main`):

- `aa-proxy/tests/proxy_integration.rs` proves redaction correctness with a
  real in-process proxy + real controlled-upstream `TcpListener` capturing
  raw bytes (`plain_http_second_keepalive_request_is_not_forwarded_uninspected`,
  line 259) — the one place an exact-byte non-leak assertion exists, but it's
  proxy-only, stops at the wire.
- `mitm_execution_evidence.rs` asserts redaction via the **audit-log record**,
  not a live upstream socket — its forwarding cases point at a dropped port.
- `aa-gateway/tests/sensitive_data_producer_test.rs` proves the gateway writes
  its own SQLite projection; `aa-api/tests/sensitive_data_analytics.rs` proves
  aa-api reads that projection — but aa-api's fixtures are seeded directly via
  `SensitiveDataProjectionWriter`, not by a live upstream gateway process.
- **No test in this repo, `e2e-public`, or `e2e-private` starts real
  aa-proxy + aa-gateway + aa-api processes and observes one redaction event
  flow live into a dashboard-visible artifact.** Producer and consumer are
  proven correct separately against a shared DB schema, never chained live.
- No test spawns the real `aasm-proxy` binary as an OS subprocess — all
  "real transport" proxy tests are in-process async server/handler code
  within the test binary itself (lower fidelity than a true black-box E2E).
- `dashboard/playwright.config.ts` `webServer.command: 'pnpm preview'` starts
  no backend; redaction-adjacent specs (`scrub-design-fidelity.spec.ts`,
  `verify-aaasm-5317.spec.ts`) are fully `page.route`-mocked.

**Registry action (AAASM-5874/5875):** this journey must be recorded with an
explicit `blocking_gap` / `pending_dependency: AAASM-5871` lifecycle state —
not simulated, not marked automated, not silently downgraded to P1/P2.

## 4. Other Epics referenced by AAASM-5872 — status, not reopened

| Ticket | Status | Relevance |
|---|---|---|
| AAASM-4452 | In Progress | Umbrella follow-up epic; several rows still `AAASM-TBD`, largely unfiled. Not this Epic's scope; reference only. |
| AAASM-4475 | In Progress | `examples` CI confirmed still mock-only by design; wants ≥1 scheduled real-gateway lane per SDK. Overlaps AAASM-5875's harness-pattern goal conceptually but is SDK-repo scoped — reconcile via registry reference, don't duplicate. |
| AAASM-4479 | Done | Skip/xfail governance — lives in `e2e-public` (`rc_pending` marker, `skip_audit.py`), not in this repo. AAASM-5876 reuses this mechanism, does not rebuild it. |
| AAASM-5526 | In Progress | Truthful-capability-boundary Epic (Core ADR 033, `governance/capability-manifest.yaml`) — no code overlap found with the release-QA-gate system. Reference only. |
| AAASM-4522 | In Progress | 50 children, 33 Done / 6 In Progress / 11 To Do (Journeys 56-62). Golden-journey source of truth; AAASM-5874 registry references it, does not duplicate its inventory. |

## 5. CI execution-integrity spot check (informs AAASM-5876)

- `ci.yml` two-layer router (`on.paths` + `dorny/paths-filter`) — no dead
  trigger found for proxy/sensitive-data/dashboard paths; the repo has
  already closed several prior dead-trigger incidents (AAASM-5677/5714/5738)
  and the pattern-matching is now bidirectional-safe.
- `dashboard-e2e-real-backend` closes the AAASM-4892 mock-drift gap for the
  dashboard's *own* backend contract, but does not cover the proxy→dashboard
  chain — a different boundary than AAASM-5871.
- No required check found with `continue-on-error`/conditional-skip that
  silently counts as PASS for a release-blocking journey; the few
  `continue-on-error: true` jobs found (`conformance-python/node/go`
  placeholders) are explicitly documented as non-blocking placeholders, not
  hidden required-check bypasses.
- `docs/release/qa-signoff/v0.0.1-rc.7.md` is currently `Verdict: BLOCK`
  (pre-existing, unrelated to this Epic — J41 was re-verified but the overall
  verdict remains BLOCK for other recorded reasons). Not this ticket's scope
  to resolve; noted for AAASM-5880 dogfood candidate selection.

## 6. Gaps this baseline hands to later Stories (not fixed here)

| Gap | Owning Story |
|---|---|
| Registry has no `lifecycle_state` / `fidelity` / `negative_control` fields | AAASM-5874 |
| No deterministic real-process harness pattern for proxy→gateway→api→dashboard | AAASM-5875 (must represent the AAASM-5871 seam as blocked, not fabricate it) |
| No registry-health CI gate (dead ref, stale evidence, unapproved skip) | AAASM-5876 |
| Release-blocking journeys lack negative-control/mutation evidence | AAASM-5877 |
| Sign-off/evidence not bound to exact registry revision + artifact digest | AAASM-5878 |
| Release relay doesn't consult the registry before tag-cut | AAASM-5879 |
| No dogfood proving BLOCK→fix→PASS on a real candidate under this system | AAASM-5880 |

## Conclusion

Baseline audit complete. No duplicate work created. One ordinary stale-doc
defect found and fixed in this PR. AAASM-5871 confirmed genuinely open and
out of this Epic's decision authority — downstream Stories must represent it
truthfully as a blocking gap, never mask it inside test infrastructure.
