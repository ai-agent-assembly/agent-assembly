import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TopologySidebar, type TopologyStats } from './TopologySidebar'
import { defaultVisibleKinds } from '../../features/topology/edgeKinds'

const STATS: TopologyStats = { active: 3, flagged: 1, crossTeam: 2, crossTeamHidden: 0, hasCycles: false }

function renderSidebar(overrides: Partial<Parameters<typeof TopologySidebar>[0]> = {}) {
  const props = {
    stats: STATS,
    teams: ['support', 'analytics'],
    filterTeam: 'all',
    onFilterTeam: vi.fn(),
    visibleKinds: defaultVisibleKinds(),
    onToggleKind: vi.fn(),
    showCrossTeam: true,
    onToggleCrossTeam: vi.fn(),
    ...overrides,
  }
  render(<TopologySidebar {...props} />)
  return props
}

describe('TopologySidebar', () => {
  it('renders the stat badges from the aggregate counters', () => {
    renderSidebar()
    expect(screen.getByTestId('topology-stat-active')).toHaveTextContent('3 active')
    expect(screen.getByTestId('topology-stat-flagged')).toHaveTextContent('1 flagged')
    expect(screen.getByTestId('topology-stat-crossteam')).toHaveTextContent('2 cross-team')
    // No cycles → no cycle badge / alert.
    expect(screen.queryByTestId('topology-stat-cycle')).toBeNull()
    expect(screen.queryByTestId('topology-cycle-alert')).toBeNull()
  })

  it('omits the flagged badge when there are no flagged agents', () => {
    renderSidebar({ stats: { ...STATS, flagged: 0 } })
    expect(screen.queryByTestId('topology-stat-flagged')).toBeNull()
  })

  it('shows the cycle badge + alert when hasCycles', () => {
    renderSidebar({ stats: { ...STATS, hasCycles: true } })
    expect(screen.getByTestId('topology-stat-cycle')).toBeInTheDocument()
    expect(screen.getByTestId('topology-cycle-alert')).toHaveTextContent('Cycle detected')
  })

  it('renders "All teams" plus one item per team and marks the active filter', () => {
    renderSidebar({ filterTeam: 'analytics' })
    const items = screen.getAllByTestId('team-filter-item')
    expect(items.map((i) => i.dataset.team)).toEqual(['all', 'support', 'analytics'])
    const active = items.find((i) => i.dataset.team === 'analytics')!
    expect(active).toHaveAttribute('data-active', 'true')
  })

  it('fires onFilterTeam when a team is clicked', async () => {
    const { onFilterTeam } = renderSidebar()
    await userEvent.click(screen.getAllByTestId('team-filter-item').find((i) => i.dataset.team === 'support')!)
    expect(onFilterTeam).toHaveBeenCalledWith('support')
  })

  it('renders all six edge kinds, every one enabled (AAASM-5099)', () => {
    renderSidebar()
    const toggles = screen.getAllByTestId('topology-edge-toggle')
    expect(toggles.map((t) => t.dataset.kind)).toEqual([
      'delegates_to', 'calls', 'reads', 'writes', 'approves', 'messages',
    ])
    // The projection now emits all six, so none is a disabled "soon" row.
    expect(toggles.every((t) => t.dataset.available === 'true')).toBe(true)
    for (const t of toggles) {
      expect(t.querySelector('input')).not.toBeDisabled()
    }
  })

  it('fires onToggleKind with the model kind for an available checkbox', async () => {
    const { onToggleKind } = renderSidebar()
    const calls = screen.getAllByTestId('topology-edge-toggle').find((t) => t.dataset.kind === 'calls')!
    await userEvent.click(calls.querySelector('input')!)
    expect(onToggleKind).toHaveBeenCalledWith('call')
  })

  it('fires onToggleKind for a newly-emitted kind too (AAASM-5099)', async () => {
    const { onToggleKind } = renderSidebar()
    const reads = screen.getAllByTestId('topology-edge-toggle').find((t) => t.dataset.kind === 'reads')!
    await userEvent.click(reads.querySelector('input')!)
    expect(onToggleKind).toHaveBeenCalledWith('reads')
  })

  it('fires onToggleCrossTeam when the cross-team toggle changes', async () => {
    const { onToggleCrossTeam } = renderSidebar()
    await userEvent.click(screen.getByTestId('topology-crossteam-toggle').querySelector('input')!)
    expect(onToggleCrossTeam).toHaveBeenCalledWith(false)
  })

  it('renders the status-stripe legend', () => {
    renderSidebar()
    const legend = screen.getByTestId('topology-status-legend')
    expect(legend).toHaveTextContent('active')
    expect(legend).toHaveTextContent('suspended')
  })
})

// AAASM-5138. The `⇆ N cross-team` stat is fleet-wide while the canvas draws a
// subset, so when they differ the sidebar has to say so — otherwise the number
// beside the picture is simply wrong.
describe('TopologySidebar — hidden cross-team crossings', () => {
  it('says nothing extra when the canvas is drawing every counted crossing', () => {
    renderSidebar({ stats: { ...STATS, crossTeam: 2, crossTeamHidden: 0 } })
    expect(screen.queryByTestId('topology-stat-crossteam-hidden')).toBeNull()
  })

  it('states how many counted crossings are not drawn', () => {
    renderSidebar({ stats: { ...STATS, crossTeam: 3, crossTeamHidden: 2 } })
    const hidden = screen.getByTestId('topology-stat-crossteam-hidden')
    expect(hidden).toHaveTextContent('2 not shown')
    expect(hidden).toHaveAttribute('data-hidden-count', '2')
    // The fleet-wide count is not quietly narrowed to match the picture.
    expect(screen.getByTestId('topology-stat-crossteam')).toHaveTextContent('3 cross-team')
  })

  it('explains why they are missing rather than just flagging a number', () => {
    renderSidebar({ stats: { ...STATS, crossTeam: 3, crossTeamHidden: 1 } })
    const title = screen.getByTestId('topology-stat-crossteam-hidden').getAttribute('title') ?? ''
    expect(title).toMatch(/team filter/i)
    expect(title).toMatch(/cross-team toggle/i)
    expect(title).toMatch(/edge type/i)
  })
})
