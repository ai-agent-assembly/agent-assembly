import { render, screen, fireEvent } from '@testing-library/react'
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
