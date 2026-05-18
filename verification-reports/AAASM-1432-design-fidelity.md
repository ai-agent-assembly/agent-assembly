# Design-fidelity verification — AAASM-1432 (F100 dashboard surfaces)

> Companion to AAASM-1129's functional AC verification. This one cross-checks
> the *rendered visual design* of the three F100 surfaces against the hi-fi
> prototype the design team approved (`design/v1/hi-fi/identity.jsx`,
> `design/v1/hi-fi/costs.jsx`, `design/v1/hi-fi/topology.jsx`,
> `design/v1/hi-fi/policy.jsx`, `design/v1/hi-fi/styles.css`).
>
> Evidence captured by three Playwright specs under `dashboard/tests/e2e/`:
>
> * `permissions-panel-design-fidelity.spec.ts`
> * `budget-burn-design-fidelity.spec.ts`
> * `violations-heatmap-design-fidelity.spec.ts`
>
> Run via `cd dashboard && pnpm test:e2e <spec-name>` to regenerate the PNGs
> under `dashboard/docs/verification/aaasm-1432/`.
>
> Viewport: 1280×800 (hi-fi reference, Playwright default Desktop Chrome).

## Summary

| Surface | Verdict |
|---|---|
| InheritedPermissionsPanel — capability tab activates | ✅ Matches |
| InheritedPermissionsPanel — allow chips use `--ok` foreground (#22592a) | ✅ Matches |
| InheritedPermissionsPanel — deny chips use `--danger` foreground (#b8291e) | ✅ Matches |
| InheritedPermissionsPanel — chip pill 12 px border-radius | ✅ Matches |
| InheritedPermissionsPanel — one `.ipp__group` per capability family | ✅ Matches |
| InheritedPermissionsPanel — empty cascade renders dedicated empty card | ✅ Matches |
| SubtreeBurnChart — card title "Budget burn · subtree" + period selector | ✅ Matches |
| SubtreeBurnChart — one stacked Area per direct child + aggregate Line | ✅ Matches |
| SubtreeBurnChart — period toggle marks active via `sbc__period-btn--active` | ✅ Matches |
| SubtreeBurnChart — BurnTooltip surfaces date + per-child rows + total | ✅ Matches |
| ViolationHeatmap — mounts at `/audit/violations` with all fixture nodes | ✅ Matches |
| ViolationHeatmap — hot spot skews red, cold-zero skews green | ✅ Matches |
| ViolationHeatmap — tooltip shows agent id + count + top policies | ✅ Matches |
| ViolationHeatmap — window selector defaults to 24h, root input empty | ✅ Matches |

## Accepted divergences (filed in PR comment)

### InheritedPermissionsPanel: tab vs. drawer container

The AAASM-1432 description says "open AgentDetailPage drawer", but AAASM-1053
shipped the panel as a **capability tab** on AgentDetailPage rather than a
right-side drawer. The visual contract for the panel itself (chips, summary
strip, cascade groups) is identical between a tab body and a drawer body —
only the outer container differs. Decision made during AAASM-1053
implementation.

### SubtreeBurnChart: stacked area vs. treemap

The AAASM-1432 description references "TopologyPage 'Subtree budget' tab,
screenshot treemap layout", but AAASM-1055 deliberately shipped a
stacked-area chart on the AgentDetailPage overview tab. The visual goal
(operators can spot which child agents dominate spend) is met by either
shape; stacked area reuses the existing recharts dep instead of pulling
d3-treemap, and the AgentDetailPage placement co-locates spend with the
agent it belongs to. Decision made during AAASM-1055 implementation; PR
\#469 captured the rationale.

## Findings

No design-fidelity regressions found. All 14 in-scope surfaces fully match
the hi-fi prototype within the spec's pixel-level assertions.

## Replay

```bash
cd dashboard
pnpm build                                                            # produce dashboard/dist
pnpm exec playwright install --with-deps chromium                     # one-time
pnpm exec playwright test permissions-panel-design-fidelity.spec.ts
pnpm exec playwright test budget-burn-design-fidelity.spec.ts
pnpm exec playwright test violations-heatmap-design-fidelity.spec.ts
```

Screenshots land at `dashboard/docs/verification/aaasm-1432/` (created on
first run by `mkdir -p` in each spec's `beforeAll`).
