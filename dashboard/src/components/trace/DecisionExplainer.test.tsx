import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { DecisionExplainer } from './DecisionExplainer'
import { NO_DATA, absent, known } from '../../lib/truthfulness'
import type { TraceEvent, TraceSeverity } from '../../features/trace/types'

const NOT_ON_SPAN =
  'TraceSpan carries only span_id, parent_span_id, operation, decision and timestamps'

/**
 * The five fields `TraceSpan` has no source for, exactly as `api.ts` maps them.
 * Fixtures start from the shape the trace API really returns, so a component
 * that only looks right against invented data fails here.
 */
const UNSOURCED = {
  payload: absent<unknown>('not-supported', NOT_ON_SPAN),
  payloadPreview: absent<string>('not-supported', NOT_ON_SPAN),
  severity: absent<TraceSeverity>('not-supported', NOT_ON_SPAN),
  redactedFields: absent<readonly string[]>('not-supported', NOT_ON_SPAN),
  violationReason: absent<string>('not-supported', NOT_ON_SPAN),
}

const SCRUBBED: TraceEvent = {
  id: 'evt-1',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'ToolCallIntercepted',
  agent: 'support-agent',
  parentSpanId: null,
  durationMs: known(12),
  decision: known('scrub'),
  ...UNSOURCED,
}

/**
 * The same span once the backend supplies payload and redaction (AAASM-5100).
 * Kept as its own fixture so the "redacted values never reach the DOM" claim
 * stays asserted through the explainer, not only in `RedactionPreview.test.tsx`.
 */
const SCRUBBED_WITH_PAYLOAD: TraceEvent = {
  ...SCRUBBED,
  payload: known({ action: 'process_refund', amount: 250, user_id: 4521 }),
  payloadPreview: known('refund > $100'),
  severity: known<TraceSeverity>('critical'),
  redactedFields: known(['user_id']),
  violationReason: known('refund > $100 requires human approval'),
}

const ALLOWED: TraceEvent = {
  id: 'evt-2',
  timestamp: '2026-04-23T14:23:03Z',
  type: 'ToolCallIntercepted',
  agent: 'support-agent',
  parentSpanId: null,
  durationMs: known(834),
  decision: known('allow'),
  ...UNSOURCED,
}

/** The ordinary audit-reconstruction case: `end_time` was never recorded. */
const NO_DURATION: TraceEvent = {
  ...ALLOWED,
  id: 'evt-3',
  durationMs: absent<number>(
    'unknown',
    'This span recorded no end time, so its duration was never measured',
  ),
}

/** Neither `decision` nor the operation names an outcome, so none is derivable. */
const NO_VERDICT: TraceEvent = {
  ...SCRUBBED,
  id: 'evt-4',
  decision: absent<string>('not-evaluated', 'This span recorded no governance decision'),
}

describe('DecisionExplainer', () => {
  it('renders the L0–L3 layer steps, outcome band, and redaction preview', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    expect(screen.getByTestId('decision-steps')).toBeInTheDocument()
    expect(screen.getAllByTestId('decision-step')).toHaveLength(4)
    expect(screen.getByTestId('decision-outcome-band')).toBeInTheDocument()
    expect(screen.getByTestId('redaction-preview')).toBeInTheDocument()
  })

  it('bands the outcome with the derived verdict and total duration', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    const explainer = screen.getByTestId('decision-explainer')
    // decision "scrub" → scrubbed. Redaction fields no longer drive the verdict.
    expect(explainer).toHaveAttribute('data-verdict', 'scrubbed')
    const band = screen.getByTestId('decision-outcome-band')
    expect(band).toHaveTextContent('SCRUBBED')
    expect(band).toHaveTextContent('12')
  })

  it('shows █ blocks for the redacted field and never leaks its value', () => {
    render(<DecisionExplainer event={SCRUBBED_WITH_PAYLOAD} />)
    expect(screen.getByTestId('redaction-block').textContent).toMatch(/^█+$/)
    expect(screen.getByTestId('redaction-preview-body').textContent).not.toContain('4521')
  })

  it('reports an unsourced payload as an absence instead of an empty body', () => {
    render(<DecisionExplainer event={SCRUBBED} />)
    // No payload field on the span → no fabricated preview, and no block to leak.
    expect(screen.queryByTestId('redaction-block')).not.toBeInTheDocument()
    expect(screen.getByTestId('redaction-preview-absent')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
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

  it('renders the absence marker for a duration that was never measured', () => {
    render(<DecisionExplainer event={NO_DURATION} />)

    const duration = screen.getByTestId('decision-duration')
    expect(duration).toHaveAttribute('data-truth-state', 'unknown')
    expect(duration).toHaveTextContent(NO_DATA)

    // AAASM-5165: an unmeasured duration must never be interpolated into the
    // band as text. Assert on the whole explainer, since any of its three
    // duration-adjacent slots would be a regression.
    const rendered = screen.getByTestId('decision-explainer').textContent ?? ''
    expect(rendered).not.toContain('null ms')
    expect(rendered).not.toContain('NaN ms')
    expect(rendered).not.toContain('undefined')
  })

  it('renders an absence instead of a coloured verdict when none was derivable', () => {
    render(<DecisionExplainer event={NO_VERDICT} />)

    expect(screen.getByTestId('decision-explainer')).toHaveAttribute('data-verdict', 'absent')

    const marker = screen.getByTestId('decision-verdict-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'not-evaluated')
    expect(marker).toHaveTextContent(NO_DATA)

    // A green ✓ ALLOWED band is not a safe default for "we do not know".
    const band = screen.getByTestId('decision-outcome-band')
    expect(band).not.toHaveTextContent('ALLOWED')
    expect(band).not.toHaveTextContent('DENIED')
  })
})
