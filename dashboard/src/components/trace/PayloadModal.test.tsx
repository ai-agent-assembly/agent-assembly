import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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
  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  afterEach(() => { vi.restoreAllMocks() })

  it('renders nothing when event is null', () => {
    const { container } = render(<PayloadModal event={null} onClose={vi.fn()} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders the pretty-printed JSON, header, Close button, and Copy button', () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)

    expect(screen.getByTestId('payload-modal')).toBeInTheDocument()
    const json = screen.getByTestId('payload-modal-json')
    expect(json.textContent).toContain('"action": "process_refund"')
    expect(json.textContent).toContain('"amount": 250')

    expect(screen.getByTestId('payload-modal-close')).toBeInTheDocument()
    expect(screen.getByTestId('payload-modal-copy')).toHaveTextContent('Copy JSON')
  })

  it('substitutes redacted fields with the sentinel string and marks the line', () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)

    const redactedRows = screen.getAllByTestId('redacted-field')
    expect(redactedRows).toHaveLength(1)
    expect(redactedRows[0]).toHaveTextContent('"user_id"')
    expect(redactedRows[0]).toHaveTextContent('"<redacted: user_id>"')
    // Real value (4521) must not leak into the rendered output for redacted fields.
    expect(redactedRows[0].textContent).not.toContain('4521')
  })

  it('shows a Redacted-by-policy tooltip on hover over the lock icon', async () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    const lock = screen.getAllByTestId('redacted-field')[0].querySelector('.payload-modal__lock')!
    await userEvent.hover(lock)
    expect(screen.getByRole('tooltip')).toHaveTextContent('Redacted by policy')
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

    await userEvent.click(screen.getByTestId('payload-modal-json'))
    expect(onClose).not.toHaveBeenCalled()
  })

  it('copies the pretty-printed JSON to clipboard and shows "Copied" feedback', async () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)

    const button = screen.getByTestId('payload-modal-copy')
    await userEvent.click(button)
    expect(navigator.clipboard.writeText).toHaveBeenCalledOnce()
    const written = vi.mocked(navigator.clipboard.writeText).mock.calls[0][0]
    expect(written).toContain('"action": "process_refund"')
    expect(button).toHaveTextContent('Copied')
  })

  it('autofocuses the Close button when the modal opens', () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)
    expect(screen.getByTestId('payload-modal-close')).toHaveFocus()
  })

  it('traps Tab focus inside the dialog (cycles from last → first and first → last)', async () => {
    render(<PayloadModal event={EVENT} onClose={vi.fn()} />)
    const close = screen.getByTestId('payload-modal-close')
    const copy = screen.getByTestId('payload-modal-copy')

    // Initial focus is on Close. Tab → Copy (the only other focusable in actions).
    expect(close).toHaveFocus()
    await userEvent.tab()
    expect(copy).toHaveFocus()

    // From last (Copy), Tab cycles back to first (Close).
    await userEvent.tab()
    expect(close).toHaveFocus()

    // Shift+Tab from first → last.
    await userEvent.tab({ shift: true })
    expect(copy).toHaveFocus()
  })
})
