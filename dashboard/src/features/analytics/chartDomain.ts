// Recharts derives each numeric axis domain from the data it is handed. A value
// like ±Number.MAX_VALUE (the schema-boundary value a malformed 200 can carry)
// or a non-finite value (NaN / ±Infinity) makes d3's tick generator emit
// degenerate, colliding ticks — producing React "duplicate key" console errors
// and a collapsed axis. Clamp every value-derived datum to a finite display
// range before it reaches Recharts. Sibling of AAASM-4195's formatDelta guard.

// Chosen well below Number.MAX_VALUE so d3 can still produce distinct, nicely
// rounded ticks across the clamped domain.
export const CHART_VALUE_LIMIT = 1e12

// Maps any number to a finite value inside ±CHART_VALUE_LIMIT: non-finite
// values (NaN / ±Infinity) collapse to 0; finite-but-extreme magnitudes clamp
// to the limit while preserving sign.
export function clampChartValue(value: number): number {
  if (!Number.isFinite(value)) return 0
  if (value > CHART_VALUE_LIMIT) return CHART_VALUE_LIMIT
  if (value < -CHART_VALUE_LIMIT) return -CHART_VALUE_LIMIT
  return value
}
