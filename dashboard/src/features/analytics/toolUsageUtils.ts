export interface ToolStat {
  name: string
  calls: number
  errorRate: number
}

// green < 1%, amber 1-5%, red > 5%
export function errorRateColor(rate: number): string {
  if (rate < 0.01) return '#10b981'
  if (rate <= 0.05) return '#f59e0b'
  return '#ef4444'
}

export function sortToolsByCallsDesc(tools: ToolStat[]): ToolStat[] {
  return [...tools].sort((a, b) => b.calls - a.calls)
}
