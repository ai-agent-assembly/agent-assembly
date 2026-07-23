import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { LayerSteps } from './LayerSteps'
import type { LayerStep } from '../../features/trace/decision'

const STEPS: LayerStep[] = [
  { id: 'l0', label: 'L0 · REQUEST', status: 'pass', detail: 'tool_call — query_db', backendGated: false },
  { id: 'l1', label: 'L1 · IDENTITY', status: 'pass', detail: 'agent support-agent', backendGated: true },
  { id: 'l2', label: 'L2 · CAPABILITY', status: 'fail', detail: 'egress blocked', backendGated: true },
  { id: 'l3', label: 'L3 · SCRUB', status: 'unreached', detail: '— not reached (blocked at L2)', backendGated: false },
]

describe('LayerSteps', () => {
  it('renders one step per layer with its label, status, and detail', () => {
    render(<LayerSteps steps={STEPS} />)
    const rows = screen.getAllByTestId('layer-step')
    expect(rows).toHaveLength(4)
    expect(rows[0]).toHaveAttribute('data-layer', 'l0')
    expect(rows[2]).toHaveAttribute('data-status', 'fail')
    expect(rows[2]).toHaveTextContent('L2 · CAPABILITY')
    expect(rows[2]).toHaveTextContent('egress blocked')
  })

  it('shows the backend-gated note only on layers that need backend fields', () => {
    render(<LayerSteps steps={STEPS} />)
    const gated = screen.getAllByTestId('layer-step-gated')
    // L1 + L2 are backendGated; L0 + L3 are not.
    expect(gated).toHaveLength(2)
    expect(gated[0]).toHaveTextContent('AAASM-5029')
  })

  it('renders a connecting rail line on every step except the last', () => {
    const { container } = render(<LayerSteps steps={STEPS} />)
    expect(container.querySelectorAll('.layer-step__line')).toHaveLength(STEPS.length - 1)
  })

  it('renders the status glyph for each of the seven states', () => {
    const all: LayerStep[] = (
      ['pass', 'fail', 'pending', 'narrow', 'scrub', 'skip', 'unreached'] as const
    ).map((status, i) => ({ id: `s${i}`, label: `S${i}`, status, detail: status, backendGated: false }))
    render(<LayerSteps steps={all} />)
    expect(screen.getAllByTestId('layer-step')).toHaveLength(7)
  })
})
