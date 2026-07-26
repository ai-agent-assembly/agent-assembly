import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { PayloadModal } from './PayloadModal'
import { NO_DATA, absent, known } from '../../lib/truthfulness'
import type { TraceEvent, TraceSeverity } from '../../features/trace/types'

const NOT_ON_SPAN =
  'TraceSpan carries only span_id, parent_span_id, operation, decision and timestamps'

/** The five fields `TraceSpan` has no source for, exactly as `api.ts` maps them. */
const UNSOURCED = {
  payload: absent<unknown>('not-supported', NOT_ON_SPAN),
  payloadPreview: absent<string>('not-supported', NOT_ON_SPAN),
  severity: absent<TraceSeverity>('not-supported', NOT_ON_SPAN),
  redactedFields: absent<readonly string[]>('not-supported', NOT_ON_SPAN),
  violationReason: absent<string>('not-supported', NOT_ON_SPAN),
}

const EVENT: TraceEvent = {
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
 * The same span once the backend supplies payload and redaction (AAASM-5100),
 * so the "redacted values never reach the DOM" claim stays asserted through the
 * modal rather than only in `RedactionPreview.test.tsx`.
 */
const EVENT_WITH_PAYLOAD: TraceEvent = {
  ...EVENT,
  payload: known({
    action: 'process_refund',
    amount: 250,
    user_id: 4521,
    notes: 'manual review',
  }),
  payloadPreview: known('refund > $100'),
  severity: known<TraceSeverity>('critical'),
  redactedFields: known(['user_id']),
  violationReason: known('refund > $100 requires human approval'),
}

/** The ordinary audit-reconstruction case: `end_time` was never recorded. */
const EVENT_NO_DURATION: TraceEvent = {
  ...EVENT,
  id: 'evt-2',
  durationMs: absent<number>(
    'unknown',
    'This span recorded no end time, so its duration was never measured',
  ),
}

describe('PayloadModal', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('renders nothing when event is null', () => {
    const { container } = render(<PayloadModal event={null} onClose={vi.fn()} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders the decision explainer body, the header verdict chip, and Close', () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)

    expect(screen.getByTestId('payload-modal')).toBeInTheDocument()
    expect(screen.getByTestId('decision-explainer')).toBeInTheDocument()
    expect(screen.getByTestId('layer-steps')).toBeInTheDocument()
    expect(screen.getByTestId('decision-outcome-band')).toBeInTheDocument()
    // decision "scrub" → scrubbed verdict on the header chip.
    expect(screen.getByTestId('verdict-chip')).toHaveAttribute('data-verdict', 'scrubbed')
    // Ratified square corners for the Trace surface (AAASM-5075).
    expect(screen.getByTestId('verdict-chip')).toHaveAttribute('data-shape', 'square')
    expect(screen.getByTestId('payload-modal-close')).toBeInTheDocument()
  })

  it('shows redacted values as █ blocks and never leaks the real value', () => {
    render(<PayloadModal event={EVENT_WITH_PAYLOAD} onClose={vi.fn()} />)

    expect(screen.getByTestId('redaction-block').textContent).toMatch(/^█+$/)
    expect(screen.getByTestId('redaction-preview-body').textContent).not.toContain('4521')
    // Non-redacted values are still shown.
    expect(screen.getByTestId('redaction-preview-body')).toHaveTextContent('process_refund')
  })

  it('renders the duration as an absence when the span was never measured', () => {
    const { container } = render(<PayloadModal event={EVENT_NO_DURATION} onClose={vi.fn()} />)

    const duration = screen.getByTestId('payload-modal-duration')
    expect(duration).not.toHaveAttribute('data-truth-state', 'known')
    expect(duration).toHaveAttribute('data-truth-state', 'unknown')
    expect(duration).toHaveTextContent(NO_DATA)

    // AAASM-5165: the subtitle used to interpolate the raw number, so an
    // unmeasured span printed "null ms" next to the agent name.
    const subtitle = container.querySelector('.payload-modal__subtitle')?.textContent ?? ''
    expect(subtitle).toContain('support-agent')
    expect(subtitle).not.toContain('null')
    expect(subtitle).not.toContain('NaN')
  })

  it('closes on Escape and on backdrop click', async () => {
    const onClose = vi.fn()
    render(<PayloadModal event={EVENT} onClose={onClose} />)

    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(1)

    await userEvent.click(screen.getByTestId('payload-modal-scrim'))
    expect(onClose).toHaveBeenCalledTimes(2)
  })

  it('does not close when clicking inside the dialog body', async () => {
    const onClose = vi.fn()
    render(<PayloadModal event={EVENT} onClose={onClose} />)

    await userEvent.click(screen.getByTestId('payload-modal-body'))
    expect(onClose).not.toHaveBeenCalled()
  })

  it('autofocuses the Close button when the modal opens', () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)
    expect(screen.getByTestId('payload-modal-close')).toHaveFocus()
  })

  it('keeps focus trapped on the sole focusable (Close) when Tab is pressed', async () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)
    const close = screen.getByTestId('payload-modal-close')

    expect(close).toHaveFocus()
    await userEvent.tab()
    expect(close).toHaveFocus()
    await userEvent.tab({ shift: true })
    expect(close).toHaveFocus()
  })
})
