import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { CapabilityFilterBar } from './CapabilityFilterBar'
import { EMPTY_FILTERS } from './filters'
import type { CapabilityAgent } from './types'

function makeAgent(patch: Partial<CapabilityAgent> = {}): CapabilityAgent {
  return {
    id: 'a',
    name: 'agent',
    framework: 'LangChain',
    owner: 'team-x',
    trust: 50,
    mode: 'enforce',
    status: 'active',
    lastSeen: '1m ago',
    caps: {},
    ...patch,
  }
}

const AGENTS: CapabilityAgent[] = [
  makeAgent({ id: 'a', framework: 'LangChain', owner: 'team-x', mode: 'enforce' }),
  makeAgent({ id: 'b', framework: 'CrewAI', owner: 'team-y', mode: 'shadow' }),
  // Duplicate framework/owner to prove uniqueSorted dedupes.
  makeAgent({ id: 'c', framework: 'LangChain', owner: 'team-x', mode: 'enforce' }),
]

describe('CapabilityFilterBar', () => {
  it('renders the visible/total count', () => {
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={vi.fn()}
        totalAgents={3}
        visibleAgents={2}
        agents={AGENTS}
      />,
    )
    expect(screen.getByText('2 of 3 agents')).toBeInTheDocument()
  })

  it('legends only the decisions the capability projection can emit', () => {
    // ADR 0026 Decision 2, signed off as option (A) under AAASM-5124. The legend
    // advertised `narrow` and `approval`; `GET /capability/matrix` projects a
    // static capability set and can emit neither, so both were a key to cells
    // that could not exist — the "aspirational legend" the ADR rejects.
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={vi.fn()}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    const legend = screen.getByRole('list', { name: 'decision legend' })
    expect([...legend.querySelectorAll('.cap-legend-item')].map((li) => li.textContent)).toEqual([
      'allow',
      'deny',
      'n/a',
    ])
    for (const removed of ['narrow', 'approval']) {
      expect(within(legend).queryByText(removed)).not.toBeInTheDocument()
      expect(legend.querySelector(`.cap-legend-sw--${removed}`)).toBeNull()
    }
  })

  it('offers no filter for a decision state at all', () => {
    // The bar filters on framework / owner / trust / mode and nothing else, so
    // "remove narrow and approval from the filters" has nothing to remove. This
    // run exists so that adding a decision filter later cannot quietly
    // reintroduce a control for a state the projection never emits.
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={vi.fn()}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    const search = screen.getByRole('search')
    const offered = [...search.querySelectorAll('option')].map((o) => o.value)
    for (const removed of ['narrow', 'approval']) {
      expect(offered).not.toContain(removed)
    }
    // No filter control is keyed on a decision at all — the legend `<ul>` is the
    // only element on the bar that mentions one, and it is not interactive. The
    // count pins the list closed, so a sixth control cannot appear unnoticed.
    const FILTER_CONTROLS = ['search agents', 'framework', 'owner', 'filter by trust at most', 'mode']
    for (const label of FILTER_CONTROLS) {
      expect(within(search).getByLabelText(label)).toBeInTheDocument()
    }
    expect(search.querySelectorAll('select, input')).toHaveLength(FILTER_CONTROLS.length)
  })

  it('builds deduped, sorted option lists for framework / owner / mode', () => {
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={vi.fn()}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    // CrewAI sorts before LangChain; each framework appears once despite a dup.
    expect(screen.getAllByRole('option', { name: 'LangChain' })).toHaveLength(1)
    expect(screen.getAllByRole('option', { name: 'CrewAI' })).toHaveLength(1)
    // mode options: enforce + shadow (deduped).
    expect(screen.getByRole('option', { name: 'enforce' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'shadow' })).toBeInTheDocument()
  })

  it('emits onChange with the new search term', () => {
    const onChange = vi.fn()
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={onChange}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    fireEvent.change(screen.getByLabelText('search agents'), {
      target: { value: 'bot' },
    })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTERS, search: 'bot' })
  })

  it('emits onChange when a framework is selected', () => {
    const onChange = vi.fn()
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={onChange}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    const frameworkSelect = screen.getByText('framework').closest('label')!
      .querySelector('select')!
    fireEvent.change(frameworkSelect, { target: { value: 'CrewAI' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTERS, framework: 'CrewAI' })
  })

  it('emits onChange when an owner is selected', () => {
    const onChange = vi.fn()
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={onChange}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    const ownerSelect = screen.getByText('owner').closest('label')!
      .querySelector('select')!
    fireEvent.change(ownerSelect, { target: { value: 'team-y' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTERS, owner: 'team-y' })
  })

  it('emits onChange when a mode is selected', () => {
    const onChange = vi.fn()
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={onChange}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    const modeSelect = screen.getByText('mode').closest('label')!
      .querySelector('select')!
    fireEvent.change(modeSelect, { target: { value: 'shadow' } })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTERS, mode: 'shadow' })
  })

  it('parses a numeric trust value into trustMax', () => {
    const onChange = vi.fn()
    render(
      <CapabilityFilterBar
        filters={EMPTY_FILTERS}
        onChange={onChange}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    fireEvent.change(screen.getByLabelText('filter by trust at most'), {
      target: { value: '70' },
    })
    expect(onChange).toHaveBeenCalledWith({ ...EMPTY_FILTERS, trustMax: 70 })
  })

  it('clears trustMax to null when the trust field is emptied', () => {
    const onChange = vi.fn()
    render(
      <CapabilityFilterBar
        filters={{ ...EMPTY_FILTERS, trustMax: 70 }}
        onChange={onChange}
        totalAgents={3}
        visibleAgents={3}
        agents={AGENTS}
      />,
    )
    fireEvent.change(screen.getByLabelText('filter by trust at most'), {
      target: { value: '' },
    })
    expect(onChange).toHaveBeenCalledWith({
      ...EMPTY_FILTERS,
      trustMax: null,
    })
  })
})
