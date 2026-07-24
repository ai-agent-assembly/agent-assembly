import type { BudgetThresholdBucket } from '../../components/topology/budgetThreshold'
import { bucketForBudget } from '../../components/topology/budgetThreshold'
import type { Approval } from '../approvals/api'
import type { BudgetTree } from '../costs/api'

/**
 * Team-level budget derived from the org→team→agent budget-inheritance tree
 * (`GET /api/v1/costs/budget-tree`, AAASM-5032). The team node carries the
 * configured daily `budget_limit_usd` and `subtree_spend_usd` (spend across the
 * team and all its agents) — the two figures a per-team budget card needs.
 *
 * `limitUsd` is `null` when the team inherits no explicit limit; `burnPct` and
 * `bucket` are then `null` because a burn ratio is meaningless without a limit.
 */
export interface TeamBudget {
  limitUsd: number | null
  spentUsd: number
  burnPct: number | null
  bucket: BudgetThresholdBucket | null
}

function parseDecimal(value: string | null | undefined): number | null {
  if (value == null) return null
  const n = Number.parseFloat(value)
  return Number.isFinite(n) ? n : null
}

/**
 * Pull the budget figures for one team out of the budget tree. Returns `null`
 * when the tree is absent or has no matching team node, which the card renders
 * as a null-safe "no budget data" state. Teams sit at depth 1 directly under
 * the org root.
 */
export function selectTeamBudget(tree: BudgetTree | undefined, teamId: string): TeamBudget | null {
  const root = tree?.root
  if (!root) return null
  const node = (root.children ?? []).find(child => child.kind === 'team' && child.id === teamId)
  if (!node) return null
  const spentUsd = parseDecimal(node.subtree_spend_usd) ?? 0
  const limitUsd = parseDecimal(node.budget_limit_usd)
  const hasLimit = limitUsd != null && limitUsd > 0
  return {
    limitUsd,
    spentUsd,
    burnPct: hasLimit ? (spentUsd / limitUsd) * 100 : null,
    bucket: hasLimit ? bucketForBudget(spentUsd, limitUsd) : null,
  }
}

/**
 * Approvals routed to a given team, newest first. Filters the approvals queue
 * (`GET /api/v1/approvals`) by `team_id`; each entry's `routing_status` carries
 * the live routing target/escalation the card surfaces. Ordering falls back to
 * insertion order when `created_at` is missing.
 */
export function selectTeamApprovals(approvals: Approval[] | undefined, teamId: string): Approval[] {
  const scoped = (approvals ?? []).filter(a => a.team_id === teamId)
  return scoped.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''))
}
