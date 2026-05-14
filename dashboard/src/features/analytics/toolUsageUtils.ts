export interface ToolStat {
  name: string
  calls: number
  errorRate: number
}

// green < 1%, amber 1-5%, red > 5%
// Returns CSS custom-property references (from styles.css); consumers
// pass these directly to SVG `fill` attributes (Recharts Cell etc.),
// which the browser resolves to the underlying hex value.
export function errorRateColor(rate: number): string {
  if (rate < 0.01) return 'var(--status-success)'
  if (rate <= 0.05) return 'var(--status-warning)'
  return 'var(--status-danger)'
}

export function sortToolsByCallsDesc(tools: ToolStat[]): ToolStat[] {
  return [...tools].sort((a, b) => b.calls - a.calls)
}
