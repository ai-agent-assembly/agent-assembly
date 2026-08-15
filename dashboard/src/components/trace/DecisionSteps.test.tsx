import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { DecisionSteps } from './DecisionSteps'
import { NO_DATA, absent, known } from '../../lib/truthfulness'
import type { DecisionStepStatus, DecisionStep } from '../../features/trace/decision'

const STEPS: DecisionStep[] = [
  {
    id: 'l0',
    label: 'L0 · REQUEST',
    status: known<DecisionStepStatus>('pass'),
    detail: known('tool_call — query_db'),
    backendGated: false,
  },
  {
    id: 'l1',
    label: 'L1 · IDENTITY',
    status: known<DecisionStepStatus>('pass'),
    detail: known('agent support-agent'),
    backendGated: true,
  },
  {
    id: 'l2',
    label: 'L2 · CAPABILITY',
    status: known<DecisionStepStatus>('fail'),
    detail: known('egress blocked'),
    backendGated: true,
  },
  {
    id: 'l3',
    label: 'L3 · SCRUB',
    status: known<DecisionStepStatus>('unreached'),
    detail: known('not reached (blocked at L2)'),
    backendGated: false,
  },
]

const NO_REDACTION_FIELD =
  'TraceSpan has no redaction field, so whether the scrub layer altered this payload was never reported'

describe('DecisionSteps', () => {
  it('renders one step per layer with its label, status, and detail', () => {
    render(<DecisionSteps steps={STEPS} />)
    const rows = screen.getAllByTestId('decision-step')
    expect(rows).toHaveLength(4)
    expect(rows[0]).toHaveAttribute('data-step', 'l0')
    expect(rows[2]).toHaveAttribute('data-status', 'fail')
    expect(rows[2]).toHaveTextContent('L2 · CAPABILITY')
    expect(rows[2]).toHaveTextContent('egress blocked')
  })

  it('shows the backend-gated note only on layers that need backend fields', () => {
    render(<DecisionSteps steps={STEPS} />)
    const gated = screen.getAllByTestId('decision-step-gated')
    // L1 + L2 are backendGated; L0 + L3 are not.
    expect(gated).toHaveLength(2)
    expect(gated[0]).toHaveTextContent('AAASM-5029')
  })

  it('renders a connecting rail line on every step except the last', () => {
    const { container } = render(<DecisionSteps steps={STEPS} />)
    expect(container.querySelectorAll('.decision-step__line')).toHaveLength(STEPS.length - 1)
  })

  it('renders the status glyph for each of the seven states', () => {
    const all: DecisionStep[] = (
      ['pass', 'fail', 'pending', 'narrow', 'scrub', 'skip', 'unreached'] as const
    ).map((status, i) => ({
      id: `s${i}`,
      label: `S${i}`,
      status: known<DecisionStepStatus>(status),
      detail: known(status),
      backendGated: false,
    }))
    render(<DecisionSteps steps={all} />)
    expect(screen.getAllByTestId('decision-step')).toHaveLength(7)
  })

  it('marks a step with no established status as absent, not as unreached', () => {
    const step: DecisionStep = {
      id: 'l3',
      label: 'L3 · SCRUB',
      status: absent<DecisionStepStatus>('not-supported', NO_REDACTION_FIELD),
      detail: absent<string>('not-supported', NO_REDACTION_FIELD),
      backendGated: false,
    }
    const { container } = render(<DecisionSteps steps={[step]} />)

    expect(screen.getByTestId('decision-step')).toHaveAttribute('data-status', 'absent')

    const marker = screen.getByTestId('decision-step-status-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'not-supported')
    expect(marker).toHaveTextContent(NO_DATA)
    expect(marker).toHaveAttribute('title', `Not supported — ${NO_REDACTION_FIELD}`)

    // `unreached` claims the layer was never entered — a finding in its own
    // right — whereas an absence says only that nothing was reported. The
    // seven-state glyph span must therefore not be rendered at all.
    expect(container.querySelector('.decision-step__icon--absent')).not.toBeNull()
    expect(container.querySelector('.decision-step__icon[aria-hidden="true"]')).toBeNull()
  })
})
