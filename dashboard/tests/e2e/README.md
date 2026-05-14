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
