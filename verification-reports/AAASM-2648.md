# AAASM-2648 — Verification: CI/CD pipeline performance doc

Verifies Story **AAASM-2648** (document the CI/CD redesign + measured GitHub
Actions data). Implementation in subtask **AAASM-2649** (PR #975); this subtask
(**AAASM-2650**) checks it against the Story acceptance criteria.

## How verified

| # | Method |
|---|--------|
| 1 | `mdbook build` runs clean on the worktree (only the unrelated mdbook-mermaid version warning); `book/benchmarks/ci-cd-pipeline-performance.html` is rendered → the page is reachable, not orphaned. |
| 2 | `docs/src/SUMMARY.md` contains `- [CI/CD Pipeline Performance](benchmarks/ci-cd-pipeline-performance.md)` under **Benchmarks**. `docs.yml` (mdBook build) is the CI gate on the impl PR. |
| 3 | Re-pulled the cited runs from the Actions REST API and recomputed the numbers — they match the page (see table below). |
| 4 | Confirmed the page states the methodology and the wall-clock-vs-deterministic caveat. |

## Data re-verification (independently recomputed from the API)

| Claim in the doc | Source run | Recomputed | Match |
|---|---|---|---|
| async-nats PR before: 23/30 jobs, 64.0 runner-min, 71.1 min | #2179 (id 26979572091) | 23 ran / 7 skip, 64.0, 71.1 | ✅ |
| async-nats PR after: 16/32 jobs, 17.3 runner-min, 10.0 min | #2283 (id 27048405455) | 16 ran / 16 skip, 17.3, 10.0 | ✅ |
| dashboard-only after: 7/31 jobs, 10.4 min | #2288 (id 27049000661) | 7 ran / 24 skip, 10.4 | ✅ |
| master push before/after runner-min: 80.8 / 44.1 | #2200 / #2292 | 80.8 / 44.1 | ✅ |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Page records the process (per-Story) + measured before/after data with run numbers | ✅ Pass | Per-Story change table + measured-results tables citing run #2179/#2283/#2180/#2288/#2200/#2292 |
| Page registered in `SUMMARY.md`; mdBook builds clean | ✅ Pass | SUMMARY entry present; `mdbook build` clean; HTML rendered; `docs.yml` is the CI gate |
| Numbers attributed to real run numbers and caveated | ✅ Pass | Every figure cites a run number; methodology section caveats wall-clock noise vs deterministic runner-min/job-count |

## Outcome

- All ACs **pass**. The documentation accurately records the redesign process and
  the measured improvement; the headline figures were **independently
  recomputed from the GitHub Actions API and match** the page.
- The improvement is real and substantial: for the common case (focused change /
  dependency bump) the pipeline performs **~73 % less compute** and returns
  **~7× sooner**, with no loss of coverage (the `CI Success` gate depends on every
  functional job).
