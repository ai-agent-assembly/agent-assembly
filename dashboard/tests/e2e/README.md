# Dashboard E2E tests

Playwright-driven end-to-end and visual regression tests for the dashboard.

## Running

The Playwright config (`dashboard/playwright.config.ts`) auto-starts `vite preview` on `http://localhost:4173` before the tests run, so build once and the tests can start:

```sh
pnpm build
pnpm test:e2e
```

To run a single spec file:

```sh
pnpm exec playwright test responsive-viewport-visual
```

## Visual regression — `responsive-viewport-visual.spec.ts`

This spec implements AAASM-1324: the AppShell layout cannot silently regress at the two canonical desktop widths (1280×800, 1920×1080) for the `/approvals`, `/agents` (Fleet), and `/policies` pages. Six snapshots total.

### Where baselines live

`dashboard/tests/e2e/responsive-viewport-visual.spec.ts-snapshots/`. Filenames follow Playwright's per-spec layout: `<route>-<viewport>-<project>-<platform>.png`.

Baselines are **platform-specific** — Playwright appends `-chromium-darwin` on macOS, `-chromium-linux` on Linux. When CI runs on a different platform than your dev box, the spec will fail until that platform's baseline is committed. Regenerate on each target platform you care about.

### Regenerating baselines (when a deliberate visual change lands)

After your code change, run:

```sh
pnpm exec playwright test responsive-viewport-visual --update-snapshots
```

That overwrites the `.png` files in the snapshots dir with the new render. Inspect the diff, confirm the change is what you intended, then commit the updated baselines.

### Masking non-deterministic regions

The spec already masks the AppShell topbar status region (which can show stream-connect timestamps) and any element flagged `data-visreg-mask`. If you add new dynamic content to a page covered by the spec, tag the volatile node:

```tsx
<span data-visreg-mask>{formattedTimestamp}</span>
```

Without the tag, the snapshot will flake on every run.

### Diff tolerance

The spec uses `maxDiffPixelRatio: 0.01` to absorb 1–2 px sub-pixel AA differences between local and CI hardware. Any real layout regression will dwarf this budget and fail the assertion.

## Theme regression — `theme-visual.spec.ts`

AAASM-2597 (follow-up to the AAASM-2595 light/dark theme). Guards the `data-theme` token system end-to-end against the real rendered app — only the network is stubbed.

Two halves:

- **Visual** — `toHaveScreenshot()` baselines for six representative pages (Fleet, Policies, Identity, Settings, Violations heatmap, Live Ops) in **both** themes, so a regression (light-on-light text, broken surface re-theme, unreadable contrast) shows up as a pixel diff. 12 snapshots in `theme-visual.spec.ts-snapshots/`, same `-chromium-<platform>` naming + masking + `maxDiffPixelRatio: 0.01` rules as above.
- **Behavioural** — the topbar toggle flips `data-theme` on `<html>` and re-themes the surface; the choice persists across reload (localStorage `aa-dashboard-theme`); the OS `prefers-color-scheme` drives the theme on first load (no stored choice); and the nav rail + code/terminal palette (`--term-*`) stay dark in **both** modes (the AAASM-2595 design intent).

Regenerate the baselines after a deliberate theme change:

```sh
pnpm exec playwright test theme-visual --update-snapshots
```

### CI lane

The **snapshot** specs — this one and `responsive-viewport-visual` — remain a **local visual gate**. Their baselines are platform-specific (`-chromium-darwin`) and no `-chromium-linux` baselines exist, so running them on a Linux runner would churn rather than verify. Run them before landing theme changes.

Everything else now runs in CI. See [Authentication](#authentication) and [CI gate](#ci-gate) below.

## Authentication

Seed the token into **`sessionStorage`**, never `localStorage`:

```ts
await page.addInitScript(() => sessionStorage.setItem('aa_token', 'e2e-test-token'))
```

`dashboard/src/auth/tokenStorage.ts` has read from `sessionStorage` only since AAASM-4322. A spec that seeds `localStorage` does not authenticate — it times out before the app mounts, with no hint that auth was the cause. That mistake silently killed 31 files for 19 days (AAASM-5191).

Note that the **theme** (`aa-dashboard-theme`) does legitimately live in `localStorage`. Only `aa_token` moved.

**Do not seed both stores "to be safe."** `localStorage` is a state production cannot reach — AAASM-4322 removed the token from it as XSS-exfiltration hardening — so a spec seeding both would keep passing if that hardening were ever reverted, and the gate would certify the vulnerability. `pnpm e2e:check-seeds` enforces this and runs as its own step in `dashboard-e2e`.

## CI gate

The `dashboard-e2e` job in `.github/workflows/ci.yml` runs this suite on any change matching the `dashboard` path filter, and is part of the `ci-success` aggregate — a red e2e run is a **merge blocker**, not an advisory signal.

It runs `dashboard/playwright.ci.config.ts`: the normal config plus a quarantine list. **Specs are gated by default** — a file must be named in that list to be excluded — so anything you add here is covered without doing anything.

If your spec is quarantined, it is because it was already failing when the gate was introduced (AAASM-5195), is a known race (AAASM-5198), or needs something the job does not provision (`hitl-approval` boots a real `aa-api` via `cargo`). Nothing is `.skip`-ed or deleted: `pnpm test:e2e` still runs the whole suite locally, quarantined specs included. Fix a spec, confirm it passes, and delete its line — removals need no ceremony. Additions do: `playwright.quarantine.ts` asserts the live list is a subset of a frozen baseline, so adding or swapping an entry fails the run until you also add it to that baseline, in the same commit, with the cause stated. Both configs load it, so `pnpm test:e2e` enforces it too.

Failures publish the HTML report, failure screenshots, retry traces and JUnit XML as build artifacts, so a CI-only failure can be diagnosed without reproducing it locally. Cost is roughly 4–5 minutes of runner time on a dashboard PR — measured at 240 tests in 44 files, about 3.8 min of suite at 2 workers plus install and browser provisioning.

The job consumes `dashboard-build`'s `dist/` artifact rather than rebuilding, so a failed build cannot leave `vite preview` serving a stale bundle the suite then passes against.

### What this gate does not prove

Stating this precisely matters more than stating it flatteringly — an
overclaiming gate is how "green CI" quietly stops meaning anything.

- **It is not an API-contract check, and its real-backend coverage is exactly
  zero.** **All 44** gated specs stub every network call — 43 via `page.route`
  directly, `violations-heatmap-design-fidelity` via the shared `mockApi()`
  helper in `_fixtures/aaasm-1432`. The gate compares the frontend against *its
  own hand-written mocks*, so it cannot observe the real API and cannot detect
  backend contract drift. The pagination-envelope breakage (AAASM-4892) is the
  proof: the app had already been updated and the **mocks** were what went stale.

  Of all 86 specs in the suite, exactly one asserts a genuine round-trip against
  a live gateway: `hitl-approval` is the only spec that uses `route.fetch` to
  proxy `/api/v1/**` to a real server, and the only one that spawns a child
  process — `hitl-fixture.ts:43` runs `cargo test --test e2e_hitl_approval` to
  boot an `aa-api`. The `dashboard-e2e` job body contains **zero** matches for
  `rust`, `cargo` or `toolchain`, so it cannot run it.

  **That single exclusion — not the other 41 — is what caps this gate's
  ceiling.** The quarantined-for-rot specs cost coverage of surfaces the gate
  otherwise watches; excluding `hitl-approval` takes an entire *category* of
  verification to zero, and no amount of working AAASM-5195 down will restore
  it. Recovering it needs a Rust-side e2e lane, not a shorter quarantine list.
- **It does not enforce the `design/v2` visual spec.** Ten gated specs pin values
  sourced from `design/v1/`. Exactly one — `review-aaasm-5149` — cites
  `design/v2/`, and even that asserts three literal RGB constants committed in
  the spec file rather than reading the design source. Nothing in the gate reads
  `design/**` at runtime, so it is a regression check on current rendered
  behaviour, not an assertion of that spec's authority.
- **It does not enforce the accessibility floor.** That is enforced by
  `AppShell.contrast.test.ts`, a **vitest** test in the `dashboard-test` job. No
  gated e2e spec makes a contrast or WCAG assertion.

### The seed guard

`pnpm e2e:check-seeds` (`dashboard/scripts/check-e2e-seeds.mjs`) runs as its own step in `dashboard-e2e`, before the browser is provisioned. It fails closed on **both** axes: an unreviewed **key** fails, and any `localStorage` access no modelled pattern consumed fails as an unmodelled **shape**. A missing or empty spec tree is a failure, not a pass.

Its one documented gap, and the conditions needed to reach it, are in the `KNOWN LIMIT` block beside `TOKEN_REBIND` in that script. Every claim there was verified by running it, not by reasoning about it — see below for why that distinction earned its own section.

### A guard fails open on whatever it does not model

The seed guard took three attempts, and the second failure is the one worth
remembering, because it looked finished.

- **v1** was a fixed-string grep. It caught 3 of 16 known write forms, and
  `grep -r` on a missing directory exits 2 — which the shell read as "no match"
  and reported as a pass.
- **v2** modelled the write shapes and allowlisted the keys. It looked
  fail-closed, and was — *on keys only*. An unrecognised key failed; an
  unrecognised **shape** matched no pattern, so the key check never ran and it
  failed **open**. Five further forms wrote the token straight past it, and the
  two that mattered needed no intent to evade: `localStorage?.setItem(...)` is
  idiomatic defensive style and `const ls = localStorage` is ordinary
  refactoring.
- **v3** inverts the default on both axes: every `localStorage` occurrence in
  executable code must be consumed by a modelled pattern, or it fails.

The generalisable rule: **when a check enumerates what is allowed, verify that
everything it does not recognise reaches the failure path.** A guard silently
declines to inspect what it cannot parse, and silence is indistinguishable from
approval. That is the same defect as an advisory e2e job, one layer down.
