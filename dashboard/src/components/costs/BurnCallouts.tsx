import './BurnCallouts.css'

export interface BurnCalloutsProps {
  /** Daily burn percentage (spend / limit * 100), or `null` when no limit is set. */
  readonly dailyPct: number | null
  /** Configured daily limit in USD, surfaced in the warning copy. */
  readonly dailyLimit: number | null
}

/**
 * Daily-burn callout banners for the Costs page (design/v1/hi-fi/costs.jsx):
 *   - ≥ 95% → danger: the limit is on track to be exhausted today.
 *   - 80–95% → warn: spend is approaching the configured limit.
 * Below 80% (or with no configured limit) nothing renders. The thresholds match
 * the shared `bucketForBudget` bands so the banner, the KPI bar colour and the
 * per-team bars all flip at the same points.
 */
export function BurnCallouts({ dailyPct, dailyLimit }: BurnCalloutsProps) {
  if (dailyPct == null) return null

  if (dailyPct >= 95) {
    return (
      <div className="costs-callout costs-callout--danger" data-testid="costs-callout-danger" role="alert">
        <div className="costs-callout__title">Daily budget critical — {dailyPct.toFixed(1)}%</div>
        At the current burn rate the daily limit will be exhausted before end of day. High-spend
        agents may be throttled.
      </div>
    )
  }

  if (dailyPct >= 80) {
    return (
      <div className="costs-callout costs-callout--warn" data-testid="costs-callout-warn" role="alert">
        <div className="costs-callout__title">Daily budget warning — {dailyPct.toFixed(1)}%</div>
        Daily spend is approaching the configured limit
        {dailyLimit == null ? '' : ` of $${dailyLimit.toFixed(2)}`}.
      </div>
    )
  }

  return null
}
