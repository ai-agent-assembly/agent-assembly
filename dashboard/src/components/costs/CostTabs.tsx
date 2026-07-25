import './CostTabs.css'

export type CostTab = 'agents' | 'teams' | 'tree'

interface CostTabsProps {
  readonly value: CostTab
  readonly onChange: (next: CostTab) => void
  /** Per-agent row count shown on the Per-agent tab. */
  readonly agentCount: number
  /** Per-team row count shown on the Per-team tab. */
  readonly teamCount: number
}

const TABS: ReadonlyArray<{ value: CostTab; label: string }> = [
  { value: 'agents', label: 'Per-agent' },
  { value: 'teams', label: 'Per-team' },
  { value: 'tree', label: 'Budget tree' },
]

/**
 * Tab bar for the Costs page, restructuring the previously-stacked per-agent /
 * per-team / budget-tree sections into tabs (design/v1/hi-fi/costs.jsx). The
 * Budget-tree tab carries no count (`null` in the mock) since the tree is a
 * hierarchy, not a flat row set.
 */
export function CostTabs({ value, onChange, agentCount, teamCount }: CostTabsProps) {
  const countFor = (tab: CostTab): number | null =>
    tab === 'agents' ? agentCount : tab === 'teams' ? teamCount : null

  return (
    <div className="costs-tabs" role="tablist" data-testid="costs-tabs">
      {TABS.map(tab => {
        const active = value === tab.value
        const count = countFor(tab.value)
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            aria-selected={active}
            data-testid={`costs-tab-${tab.value}`}
            className={`costs-tab${active ? ' costs-tab--active' : ''}`}
            onClick={() => onChange(tab.value)}
          >
            {tab.label}
            {count != null && <span className="costs-tab__count">{count}</span>}
          </button>
        )
      })}
    </div>
  )
}
