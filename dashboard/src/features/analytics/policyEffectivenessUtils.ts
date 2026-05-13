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

// Color stops matching CSS variables --heatmap-low / --heatmap-mid / --heatmap-high
const LOW: [number, number, number] = [16, 185, 129]   // #10b981 green
const MID: [number, number, number] = [245, 158, 11]   // #f59e0b amber
const HIGH: [number, number, number] = [239, 68, 68]   // #ef4444 red

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
