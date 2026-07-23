import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { DecisionExplainer } from './DecisionExplainer'
import type { TraceEvent } from '../../features/trace/types'

const SCRUBBED: TraceEvent = {
  id: 'evt-1',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'policy_violation',
  agent: 'support-agent',
  durationMs: 12,
  payloadPreview: 'refund > $100',
  payload: { action: 'process_refund', amount: 250, user_id: 4521 },
  severity: 'critical',
  redactedFields: ['user_id'],
  violationReason: 'refund > $100 requires human approval',
}

const ALLOWED: TraceEvent = {
  id: 'evt-2',
  timestamp: '2026-04-23T14:23:03Z',
  type: 'llm_call',
  agent: 'support-agent',
  durationMs: 834,
  payloadPreview: 'GPT-4o · query billing',
  payload: { model: 'gpt-4o' },
  severity: 'info',
}

describe('DecisionExplainer', () => {
  it('renders the L0–L3 layer steps, outcome band, and redaction preview', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    expect(screen.getByTestId('layer-steps')).toBeInTheDocument()
    expect(screen.getAllByTestId('layer-step')).toHaveLength(4)
    expect(screen.getByTestId('decision-outcome-band')).toBeInTheDocument()
    expect(screen.getByTestId('redaction-preview')).toBeInTheDocument()
  })

  it('bands the outcome with the derived verdict and total duration', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    const explainer = screen.getByTestId('decision-explainer')
    // redactedFields present → scrubbed.
    expect(explainer).toHaveAttribute('data-verdict', 'scrubbed')
    const band = screen.getByTestId('decision-outcome-band')
    expect(band).toHaveTextContent('SCRUBBED')
    expect(band).toHaveTextContent('12')
  })

  it('shows █ blocks for the redacted field and never leaks its value', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    expect(screen.getByTestId('redaction-block').textContent).toMatch(/^█+$/)
    expect(screen.getByTestId('redaction-preview-body').textContent).not.toContain('4521')
  })

  it('renders explicit backend-gated notes for policy link and trace_id chain', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    expect(screen.getByTestId('decision-policy-gated')).toHaveTextContent('backend-gated')
    expect(screen.getByTestId('decision-backend-note')).toHaveTextContent('AAASM-5029')
  })

  it('bands an untouched call as ALLOWED with no redaction tags', () => {
    render(<DecisionExplainer event={ALLOWED} />)
    expect(screen.getByTestId('decision-explainer')).toHaveAttribute('data-verdict', 'allowed')
    expect(screen.getByTestId('decision-outcome-band')).toHaveTextContent('ALLOWED')
    expect(screen.queryByTestId('redaction-tags')).not.toBeInTheDocument()
  })
})
