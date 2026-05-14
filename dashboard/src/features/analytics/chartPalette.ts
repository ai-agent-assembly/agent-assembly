/**
 * Chart series colour palettes.
 *
 * Values are sourced from CSS custom properties (`--chart-cat-*`, `--chart-cb-*`)
 * defined in `dashboard/src/styles.css`, resolved at module load via
 * `getComputedStyle`. This keeps a single source of truth for chart palette
 * tokens; consumers (Recharts components, FleetHealthPanel sparkline, etc.)
 * continue to receive plain hex strings via the unchanged `readonly string[]`
 * export shape.
 *
 * `getComputedStyle` returns the substituted/computed value of CSS custom
 * properties on `:root`, so aliases like `var(--status-success)` resolve to
 * the underlying hex automatically.
 */

const CHART_CATEGORICAL_VARS: readonly string[] = [
  '--chart-cat-1',
  '--chart-cat-2',
  '--chart-cat-3',
  '--chart-cat-4',
  '--chart-cat-5',
  '--chart-cat-6',
  '--chart-cat-7',
  '--chart-cat-8',
  '--chart-cat-9',
  '--chart-cat-10',
  '--chart-cat-11',
  '--chart-cat-12',
]

// Wong (2011) colorblind-safe palette — distinguishable under deuteranopia/protanopia.
const CHART_COLORBLIND_VARS: readonly string[] = [
  '--chart-cb-1',
  '--chart-cb-2',
  '--chart-cb-3',
  '--chart-cb-4',
  '--chart-cb-5',
  '--chart-cb-6',
  '--chart-cb-7',
]

function resolvePalette(varNames: readonly string[]): string[] {
  if (typeof document === 'undefined') return varNames.map(() => '')
  const root = getComputedStyle(document.documentElement)
  return varNames.map((v) => root.getPropertyValue(v).trim())
}

export const CHART_CATEGORICAL_PALETTE: string[] = resolvePalette(CHART_CATEGORICAL_VARS)
export const CHART_COLORBLIND_PALETTE: string[] = resolvePalette(CHART_COLORBLIND_VARS)
