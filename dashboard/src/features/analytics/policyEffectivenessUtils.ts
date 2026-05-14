export interface PolicyDay {
  date: string
  blocks: number
  warns: number
  passes: number
}

export interface PolicyRule {
  id: string
  name: string
  days: PolicyDay[]
}

export function computeRatio(day: PolicyDay): number {
  const total = day.blocks + day.warns + day.passes
  return total === 0 ? 0 : day.blocks / total
}

// Heatmap colour stops are sourced from CSS custom properties
// --heatmap-low / --heatmap-mid / --heatmap-high declared in
// dashboard/src/styles.css. getComputedStyle returns the substituted
// value (resolving var(--status-success/-warning/-danger)), and we
// parse it into a numeric RGB triple for lerp().

const FALLBACK_LOW: [number, number, number] = [16, 185, 129]
const FALLBACK_MID: [number, number, number] = [245, 158, 11]
const FALLBACK_HIGH: [number, number, number] = [239, 68, 68]

function rgbFromCssVar(
  varName: string,
  fallback: [number, number, number],
): [number, number, number] {
  if (typeof document === 'undefined') return fallback
  const hex = getComputedStyle(document.documentElement)
    .getPropertyValue(varName)
    .trim()
    .replace(/^#/, '')
  const m = hex.match(/^([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})$/)
  if (!m) return fallback
  return [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)]
}

const LOW = rgbFromCssVar('--heatmap-low', FALLBACK_LOW)
const MID = rgbFromCssVar('--heatmap-mid', FALLBACK_MID)
const HIGH = rgbFromCssVar('--heatmap-high', FALLBACK_HIGH)

function lerp(a: number, b: number, t: number): number {
  return Math.round(a + (b - a) * t)
}

export function ratioToColor(ratio: number): string {
  const clamped = Math.max(0, Math.min(1, ratio))
  let r: number, g: number, b: number
  if (clamped <= 0.5) {
    const t = clamped * 2
    r = lerp(LOW[0], MID[0], t)
    g = lerp(LOW[1], MID[1], t)
    b = lerp(LOW[2], MID[2], t)
  } else {
    const t = (clamped - 0.5) * 2
    r = lerp(MID[0], HIGH[0], t)
    g = lerp(MID[1], HIGH[1], t)
    b = lerp(MID[2], HIGH[2], t)
  }
  return `rgb(${r},${g},${b})`
}

export function computeRowTotals(rules: PolicyRule[]): Map<string, number> {
  const totals = new Map<string, number>()
  for (const rule of rules) {
    totals.set(rule.id, rule.days.reduce((s, d) => s + d.blocks, 0))
  }
  return totals
}

export function sortRulesByBlocks(
  rules: PolicyRule[],
  totals: Map<string, number>,
  asc: boolean,
): PolicyRule[] {
  return [...rules].sort((a, b) => {
    const diff = (totals.get(a.id) ?? 0) - (totals.get(b.id) ?? 0)
    return asc ? diff : -diff
  })
}

export function collectDates(rules: PolicyRule[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const rule of rules) {
    for (const d of rule.days) {
      if (!seen.has(d.date)) {
        seen.add(d.date)
        result.push(d.date)
      }
    }
  }
  return result.sort()
}
