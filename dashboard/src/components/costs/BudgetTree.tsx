import { useState } from 'react'
import type { BudgetTree as BudgetTreeData, BudgetTreeNode } from '../../features/costs/api'
import './BudgetTree.css'

/** Map a subtree-burn percentage to its severity token. */
function burnColor(pct: number): string {
  if (pct >= 85) return 'var(--danger)'
  if (pct >= 70) return 'var(--warn)'
  return 'var(--ok)'
}

function num(value: string | null | undefined): number {
  return value == null ? 0 : Number.parseFloat(value) || 0
}

/** Ids expanded by default: the org root and every team (depth ≤ 1). */
function defaultExpanded(node: BudgetTreeNode, acc: Set<string> = new Set()): Set<string> {
  if (node.depth <= 1) acc.add(node.id)
  for (const child of node.children) defaultExpanded(child, acc)
  return acc
}

/** Disclosure glyph for a row: a caret when it has children, a dot for a leaf. */
function caretGlyph(hasKids: boolean, open: boolean): string {
  if (!hasKids) return '·'
  return open ? '▾' : '▸'
}

interface RowMetrics {
  readonly limit: number
  readonly own: number
  readonly subtree: number
  readonly totalPct: number
  readonly ownPct: number
  readonly childPct: number
  readonly parentPct: number | null
  readonly color: string
}

/**
 * Derive the spend/limit percentages a row renders. A subtree burn is capped at
 * 100%; the own-spend band never overflows the remaining track. `parentPct` is
 * null at the root (no parent budget to consume a share of).
 */
function rowMetrics(node: BudgetTreeNode, parentLimit: number): RowMetrics {
  const limit = num(node.budget_limit_usd)
  const own = num(node.own_spend_usd)
  const subtree = num(node.subtree_spend_usd)
  const childSpend = Math.max(0, subtree - own)

  const totalPct = limit > 0 ? Math.min(100, (subtree / limit) * 100) : 0
  const ownPct = limit > 0 ? Math.min(100, (own / limit) * 100) : 0
  const childPct = limit > 0 ? Math.min(100 - ownPct, (childSpend / limit) * 100) : 0
  const parentPct = parentLimit > 0 ? Math.min(100, (subtree / parentLimit) * 100) : null

  return { limit, own, subtree, totalPct, ownPct, childPct, parentPct, color: burnColor(totalPct) }
}

interface BurnMeterProps {
  readonly totalPct: number
  readonly ownPct: number
  readonly childPct: number
  readonly color: string
  readonly showSub: boolean
}

/** Subtree-burn cell: total percent, an optional sub-agent share, and the bar. */
function BurnMeter({ totalPct, ownPct, childPct, color, showSub }: BurnMeterProps) {
  return (
    <div className="budget-tree__burn">
      <div className="budget-tree__burn-meta">
        <span style={{ color, fontWeight: 600 }}>{totalPct.toFixed(1)}%</span>
        {showSub && <span className="budget-tree__burn-sub">+{childPct.toFixed(0)}% sub-agents</span>}
      </div>
      <div className="budget-tree__burn-track">
        <div className="budget-tree__burn-total" style={{ width: `${totalPct}%`, background: color }} />
        {ownPct > 0 && (
          <div className="budget-tree__burn-own" style={{ width: `${ownPct}%`, background: color }} />
        )}
      </div>
    </div>
  )
}

interface RowProps {
  readonly node: BudgetTreeNode
  readonly parentLimit: number
  readonly expanded: ReadonlySet<string>
  readonly onToggle: (id: string) => void
}

/**
 * One budget-tree row plus, when expanded, its children. Shows the node's own
 * spend, subtree spend, configured limit, a subtree-burn bar (own spend solid,
 * sub-agent spend as a lighter band), and its share of the parent's budget.
 * Colours are theme tokens so the row inverts with `data-theme`.
 */
function BudgetRow({ node, parentLimit, expanded, onToggle }: RowProps) {
  const hasKids = node.children.length > 0
  const open = expanded.has(node.id)
  const m = rowMetrics(node, parentLimit)

  const toggle = hasKids ? () => onToggle(node.id) : undefined
  const parentColor = m.parentPct != null && m.parentPct >= 70 ? { color: m.color } : undefined

  return (
    <>
      <div
        className={`budget-tree__row${m.totalPct >= 85 ? ' budget-tree__row--critical' : ''}`}
        role="row"
        data-testid={`budget-node-${node.id}`}
        data-kind={node.kind}
        onClick={toggle}
        style={{ cursor: hasKids ? 'pointer' : 'default' }}
      >
        <div className="budget-tree__name" style={{ paddingLeft: `${node.depth * 18}px` }}>
          <span className="budget-tree__caret" aria-hidden="true">
            {caretGlyph(hasKids, open)}
          </span>
          <span className={`budget-tree__kind budget-tree__kind--${node.kind}`}>{node.kind}</span>
          <span className="budget-tree__label" title={node.label}>
            {node.label}
          </span>
          {node.governance_level && <span className="budget-tree__gov">{node.governance_level}</span>}
        </div>

        <div className="budget-tree__own">{m.own > 0 ? `$${m.own.toFixed(2)}` : '—'}</div>
        <div className="budget-tree__subtree" style={{ color: m.color }}>
          ${m.subtree.toFixed(2)}
        </div>
        <div className="budget-tree__limit">{m.limit > 0 ? `$${m.limit.toFixed(0)}` : '—'}</div>

        <BurnMeter
          totalPct={m.totalPct}
          ownPct={m.ownPct}
          childPct={m.childPct}
          color={m.color}
          showSub={hasKids && m.childPct > 1}
        />

        <div className="budget-tree__parent" style={parentColor}>
          {m.parentPct != null ? `${m.parentPct.toFixed(0)}%` : '—'}
        </div>
      </div>

      {hasKids &&
        open &&
        node.children.map(child => (
          <BudgetRow key={child.id} node={child} parentLimit={m.limit} expanded={expanded} onToggle={onToggle} />
        ))}
    </>
  )
}

/**
 * Org → team → agent budget-inheritance tree (AAASM-5032). Expandable: a parent's
 * budget constrains its whole subtree, so each row surfaces subtree spend and the
 * share of the parent budget it consumes. Presentational — the parent owns the
 * query so it can be spied in tests — with honest loading / error / empty states.
 */
export function BudgetTree({
  data,
  isLoading,
  isError,
}: Readonly<{ data: BudgetTreeData | undefined; isLoading: boolean; isError: boolean }>) {
  const root = data?.root ?? null
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set())
  const [seeded, setSeeded] = useState(false)

  // Seed the default-expanded set once the root arrives (org + teams open).
  if (root && !seeded) {
    setExpanded(defaultExpanded(root))
    setSeeded(true)
  }

  const onToggle = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  let body
  if (isLoading) {
    body = (
      <p className="budget-tree__note" data-testid="budget-tree-loading">
        Loading budget tree…
      </p>
    )
  } else if (isError) {
    body = (
      <p className="budget-tree__note" data-testid="budget-tree-error">
        Budget tree unavailable.
      </p>
    )
  } else if (!root) {
    body = (
      <p className="budget-tree__note" data-testid="budget-tree-empty">
        No budget data to display.
      </p>
    )
  } else {
    body = (
      <div className="budget-tree__grid" role="table" data-testid="budget-tree-grid">
        <div className="budget-tree__row budget-tree__row--head" role="row">
          <div className="budget-tree__name">Node</div>
          <div className="budget-tree__own">Own spend</div>
          <div className="budget-tree__subtree">Subtree</div>
          <div className="budget-tree__limit">Limit</div>
          <div className="budget-tree__burn">Subtree burn</div>
          <div className="budget-tree__parent">% parent</div>
        </div>
        <BudgetRow node={root} parentLimit={0} expanded={expanded} onToggle={onToggle} />
      </div>
    )
  }

  return (
    <section className="budget-tree" data-testid="budget-tree">
      <div className="budget-tree__intro">
        <strong>Subtree spend</strong> = a node's own spend plus every spawned descendant's. A parent's
        budget constrains the whole subtree — exceeding it blocks all children regardless of their own
        limits.
      </div>
      {body}
    </section>
  )
}
