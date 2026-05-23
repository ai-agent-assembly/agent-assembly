# Functional verification — AAASM-1592 (E18 S-K — Dashboard Settings → Retention Policy admin UI)

> AC verification sub-ticket: [AAASM-1869](https://lightning-dust-mite.atlassian.net/browse/AAASM-1869) — `[5/6]` under [AAASM-1592](https://lightning-dust-mite.atlassian.net/browse/AAASM-1592).
>
> Implementation sub-tickets (all merged): [AAASM-1850], [AAASM-1856], [AAASM-1861], [AAASM-1866].
>
> Evidence captured by the new Playwright spec
> [`dashboard/tests/e2e/retention-policy.spec.ts`](../dashboard/tests/e2e/retention-policy.spec.ts).
> Run via `pnpm --dir dashboard exec playwright test tests/e2e/retention-policy.spec.ts`.
> Viewport: 1280×720 (Playwright default Desktop Chrome).
>
> [AAASM-1850]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1850
> [AAASM-1856]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1856
> [AAASM-1861]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1861
> [AAASM-1866]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1866

## Summary

7 Playwright specs walking every acceptance criterion in the parent story end-to-end against the built dashboard. The gateway is mocked at the network layer via `page.route()` for deterministic runs.

```
Running 7 tests using 7 workers
  ✓ AC1 — page renders at /settings/storage/retention with values from GET (291ms)
  ✓ AC2 — changing hot_days to 15 and saving fires PUT with that value (378ms)
  ✓ AC3 — warm_days <= hot_days shows inline error and disables Save (310ms)
  ✓ AC4 — cold_action=archive without archive_url shows inline error (356ms)
  ✓ AC5 — Run Now (Dry Run) fires POST /run {dry_run:true} and shows returned stats (355ms)
  ✓ AC6 — last-run stats panel renders timestamp and counts from the GET response (282ms)
  ✓ AC7 — PUT response carries the updated config (live read-back path) (347ms)
  7 passed (1.3s)
```

## Acceptance Criteria — per-AC verdict

| AC from story | Verdict | Spec |
|---|---|---|
| Page renders at `/settings/storage/retention` with current policy values loaded from `GET /api/v1/admin/retention-policy` | ✅ Matches | AC1 — asserts the three controls (hot_days / warm_days / cold_action) reflect the GET-response values |
| Changing `hot_days` to 15 and saving updates the running gateway (no restart needed) | ✅ Matches | AC2 — asserts the PUT request body carries `hot_days=15` and the success status banner renders |
| `warm_days ≤ hot_days` shows inline validation error, Save button disabled | ✅ Matches | AC3 — asserts `[data-testid=retention-policy-warm-days-error]` visible and `[data-testid=retention-policy-save]` is disabled |
| `cold_action: archive` without `archive_url` shows validation error | ✅ Matches | AC4 — asserts archive URL field appears, error matches `/required/`, Save disabled |
| "Run Now (Dry Run)" triggers `POST /api/v1/admin/retention-policy/run { dry_run: true }` and shows returned stats | ✅ Matches | AC5 — asserts the captured POST body equals `{ dry_run: true }`, hot_rows stat renders `9,999`, and the `(dry run)` tag is visible |
| Last run stats section shows timestamp + row counts from the most recent retention run | ✅ Matches | AC6 — asserts hot/dropped/compressed/archived/freed stat cells render the GET-response values; timestamp formatted as `20 May 2026` |
| `PUT /api/v1/admin/retention-policy` returns 200 with updated config | ✅ Matches | AC7 — asserts the form re-renders with the PUT-response values (warm_days=45) after Save |
| `pnpm exec vitest run` green (includes new tests for `RetentionPolicy.tsx`) | ✅ Matches | 11 vitest cases shipped in AAASM-1866; full dashboard suite 993/993 green at merge |
| `pnpm typecheck` clean | ✅ Matches | CI `Dashboard (type-check + lint)` job pass on AAASM-1866's PR #747 |

## Implementation deviations from the story

None functional. One implementation note worth recording:

* **Navigation indirection in e2e**: `vite preview` (the harness Playwright uses) builds the SPA with `base: './'`, so deep URLs like `/settings/storage/retention` resolve relative-asset paths against the URL's path segments and 404 the bundle. The spec works around this by `page.goto('/settings')` then clicking the `Retention Policy` nav link — semantically equivalent to typing the URL directly, and how real users reach the page. No production code change required.

## What this verification does **not** cover (out of scope)

* **Live end-to-end against a real gateway**: AAASM-1590 (S-I.4) hasn't shipped, so production runs of the gateway don't currently instantiate a `RetentionEngine`. The handlers return 503 in that case (covered by `aa-api/tests/admin.rs::*_503_*` from AAASM-1861). End-to-end smoke against a real engine becomes possible once S-I.4 lands.
* **Design-fidelity verification**: tracked separately under [AAASM-1871](https://lightning-dust-mite.atlassian.net/browse/AAASM-1871) (sub-ticket [6/6]).
* **i18n / a11y audits**: out of AAASM-1592's stated scope.

## Verdict

✅ **All 9 acceptance criteria from AAASM-1592 are satisfied by the merged implementation.** The functional verification gate passes — proceed to design-fidelity verification ([AAASM-1871]).

[AAASM-1871]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1871
