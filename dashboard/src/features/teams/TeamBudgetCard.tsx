import { budgetBucketColor } from './budgetColor'
import type { TeamBudget } from './detailData'

interface TeamBudgetCardProps {
  budget: TeamBudget | null
  isLoading: boolean
}

/**
 * Daily budget-usage card for the selected team. Backed by the budget tree
 * (`GET /api/v1/costs/budget-tree`). Renders a null-safe empty state when the
 * team inherits no explicit daily limit — the OSS API exposes no team-level
 * monthly limit, so only the daily period is shown.
 */
export function TeamBudgetCard({ budget, isLoading }: Readonly<TeamBudgetCardProps>) {
  return (
    <section className="teams-card" data-testid="team-budget-card" aria-label="Budget usage">
      <div className="teams-card__title">Budget usage</div>

      {isLoading && (
        <div className="teams-card__empty" data-testid="team-budget-loading">Loading budget…</div>
      )}

      {!isLoading && (budget == null || budget.limitUsd == null) && (
        <div className="teams-card__empty" data-testid="team-budget-empty">
          {budget == null
            ? 'No budget data for this team.'
            : `Spent $${budget.spentUsd.toFixed(2)} — no daily limit configured.`}
        </div>
      )}

      {!isLoading && budget != null && budget.limitUsd != null && (
        <div className="teams-budget-grid" data-testid="team-budget-daily">
          <div>
            <div className="teams-budget-amount" style={{ color: budgetBucketColor(budget.bucket) }}>
              ${budget.spentUsd.toFixed(2)}
              <span className="teams-budget-amount__limit"> / ${budget.limitUsd.toFixed(0)} daily</span>
            </div>
            <div className="teams-budget-track">
              <div
                className="teams-budget-track__fill"
                data-testid="team-budget-bar-fill"
                style={{
                  width: `${Math.min(100, budget.burnPct ?? 0)}%`,
                  background: budgetBucketColor(budget.bucket),
                }}
              />
            </div>
            <div className="teams-budget-pct" data-testid="team-budget-pct">
              {(budget.burnPct ?? 0).toFixed(1)}% used
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
