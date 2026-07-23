import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { PayloadModal } from './PayloadModal'
import type { TraceEvent } from '../../features/trace/types'

const EVENT: TraceEvent = {
  id: 'evt-1',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'policy_violation',
  agent: 'support-agent',
  durationMs: 12,
  payloadPreview: 'refund > $100',
  payload: {
    action: 'process_refund',
    amount: 250,
    user_id: 4521,
    notes: 'manual review',
  },
  severity: 'critical',
  redactedFields: ['user_id'],
  violationReason: 'refund > $100 requires human approval',
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
    // redactedFields present → scrubbed verdict on the header chip.
    expect(screen.getByTestId('verdict-chip')).toHaveAttribute('data-verdict', 'scrubbed')
    expect(screen.getByTestId('payload-modal-close')).toBeInTheDocument()
  })

  it('shows redacted values as █ blocks and never leaks the real value', () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)

    expect(screen.getByTestId('redaction-block').textContent).toMatch(/^█+$/)
    expect(screen.getByTestId('redaction-preview-body').textContent).not.toContain('4521')
    // Non-redacted values are still shown.
    expect(screen.getByTestId('redaction-preview-body')).toHaveTextContent('process_refund')
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
