/**
 * The drill-down list, the action detail, and the compliance export
 * (AAASM-5360).
 *
 * ## Falsification record
 *
 *  - **M-O — render the prevention boolean directly.** Replace the events
 *    table's `prevention.label` with `event.prevented_transmission ? 'Yes' :
 *    'No'`. **2 failed, 15 passed (17):**
 *    `does not render a row with no transmission evidence as "not prevented"`
 *    and `distinguishes a measured negative from an absent measurement, row by row`.
 *  - **M-P — pair `total` with the page length as bare numbers.** Replace the
 *    coverage sentence with `{rows.length} / {total}`. **2 failed, 15 passed
 *    (17):** `says what is not on the page when the list is truncated` and
 *    `says so when the page is the whole matching set`.
 *  - **M-Q — default the export acknowledgement.** Remove the `disabled` guard
 *    on the export button *and* pass `true` to `requestComplianceExport`.
 *    **1 failed, 16 passed (17):** `does not offer the export until it has been
 *    acknowledged`. `sends the acknowledgement the operator actually gave`
 *    survives, because that test ticks the box first and so the value it asserts
 *    is `true` either way — recorded here rather than claimed as a second proof.
 *    The argument-level guard is proved separately by M-E in `api.test.ts`.
 *
 * Three mutations, three disjoint sets of tests.
 *
 * A note on what is *not* asserted: there is no test that the API omits offsets
 * and lengths — that is AAASM-5359's contract, and asserting it from a fixture
 * here would only assert the fixture. What is asserted is the second line of
 * defence: `schema.test.ts` proves such a field is stripped before a component
 * can read it, and `renders a finding by name and label, never by position`
 * proves nothing here reconstructs one.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { EventDetailPanel } from './EventDetailPanel'
import { EventsPanel } from './EventsPanel'
import { ExportPanel } from './ExportPanel'
import { DEFAULT_FILTERS } from './filters'
import { EVENT, FINDINGS, SCOPE } from './__tests__/fixtures'

const getMock = vi.fn()

vi.mock('../../api/client', () => ({
  api: { GET: (...args: unknown[]) => getMock(...args) },
}))

beforeEach(() => {
  getMock.mockReset()
})

/** The same action, but with transmission evidence recorded. */
const MEASURED_EVENT = {
  ...EVENT,
  event_id: 'evt-0002',
  transmission_evidence: 'forwarded',
  prevented_transmission: false,
}

describe('EventsPanel', () => {
  it('does not render a row with no transmission evidence as "not prevented"', () => {
    // `prevented_transmission` is `false` on this row, and it is `false` because
    // nothing looked. Printing that as a negative describes a product failing to
    // prevent things, for a product not measuring whether it does.
    render(
      <EventsPanel
        events={known({ scope: SCOPE, total: 1, events: [EVENT] })}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    const cell = screen.getByTestId('sd-event-prevention-evt-0001')
    expect(cell).toHaveAttribute('data-prevention', 'unmeasured')
    expect(cell).toHaveTextContent('Not measured')
    expect(cell.textContent).not.toMatch(/^No$/)
    expect(cell.getAttribute('title')).toContain(
      'This is not a finding that it was not prevented.',
    )
  })

  it('distinguishes a measured negative from an absent measurement, row by row', () => {
    render(
      <EventsPanel
        events={known({ scope: SCOPE, total: 2, events: [EVENT, MEASURED_EVENT] })}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    const unmeasured = screen.getByTestId('sd-event-prevention-evt-0001')
    const measured = screen.getByTestId('sd-event-prevention-evt-0002')
    expect(unmeasured).toHaveAttribute('data-prevention', 'unmeasured')
    expect(measured).toHaveAttribute('data-prevention', 'not-prevented')
    expect(unmeasured.textContent).not.toBe(measured.textContent)
    expect(measured.getAttribute('title')).toContain('a measured negative')
  })

  it('says what is not on the page when the list is truncated', () => {
    render(
      <EventsPanel
        events={known({ scope: SCOPE, total: 940, events: [EVENT] })}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    const coverage = screen.getByTestId('sd-events-coverage')
    expect(coverage).toHaveAttribute('data-truncated', 'true')
    expect(coverage).toHaveTextContent('Showing 1 of 940 matching actions')
    expect(coverage).toHaveTextContent('counted in the figures above but are not on this page')
  })

  it('says so when the page is the whole matching set', () => {
    render(
      <EventsPanel
        events={known({ scope: SCOPE, total: 1, events: [EVENT] })}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    const coverage = screen.getByTestId('sd-events-coverage')
    expect(coverage).toHaveAttribute('data-truncated', 'false')
    expect(coverage).toHaveTextContent('Showing all 1 matching action')
  })

  it('renders the per-row finding count with its unit', () => {
    render(
      <EventsPanel
        events={known({ scope: SCOPE, total: 1, events: [EVENT] })}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    expect(screen.getByTestId('sd-event-findings-evt-0001')).toHaveTextContent('3 findings')
  })

  it('separates an empty window from a filtered-out one', () => {
    const empty = known({ scope: SCOPE, total: 0, events: [] })
    const { unmount } = render(
      <EventsPanel
        events={empty}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    expect(screen.getByTestId('sd-events-empty')).toHaveTextContent(
      'No sensitive data recorded in this window',
    )
    unmount()

    render(
      <EventsPanel
        events={empty}
        activeFilterCount={3}
        selectedEventId={null}
        onSelectEvent={vi.fn()}
      />,
    )
    expect(screen.getByTestId('sd-events-empty')).toHaveTextContent('No action matched these filters')
  })

  it('opens the detail for the row that was clicked', () => {
    const onSelectEvent = vi.fn()
    render(
      <EventsPanel
        events={known({ scope: SCOPE, total: 1, events: [EVENT] })}
        activeFilterCount={0}
        selectedEventId={null}
        onSelectEvent={onSelectEvent}
      />,
    )
    fireEvent.click(screen.getByTestId('sd-event-open-evt-0001'))
    expect(onSelectEvent).toHaveBeenCalledWith('evt-0001')
  })
})

describe('EventDetailPanel', () => {
  const detail = known({ event: EVENT, findings: FINDINGS })

  it('renders a finding by name and label, never by position', () => {
    render(<EventDetailPanel detail={detail} onClose={vi.fn()} />)
    const findings = screen.getByTestId('sd-event-detail-findings')

    // What §9 grants in place of an offset: the field's name, and the label the
    // value was replaced with.
    expect(findings).toHaveTextContent('body.text')
    expect(findings).toHaveTextContent('[REDACTED:AwsAccessKey]')

    // ...and nothing that could locate or reveal the value. The column headers
    // are the whole vocabulary, so a positional column would be visible here.
    const headers = [...findings.querySelectorAll('th')].map((th) => th.textContent)
    expect(headers).toEqual([
      '#',
      'Category',
      'Severity',
      'Confidence',
      'Detection method',
      'Triage status',
      'Recognizer',
      'Field path',
      'Redaction label',
    ])
    for (const banned of ['offset', 'Offset', 'length', 'Length', 'byte', 'Value']) {
      expect(headers.join(' ')).not.toContain(banned)
    }
  })

  it('shows the three §8 evidence columns beside the derived prevention verdict', () => {
    render(<EventDetailPanel detail={detail} onClose={vi.fn()} />)
    const evidence = screen.getByTestId('sd-event-detail-evidence')
    expect(evidence).toHaveTextContent('Enforcement point (condition 1)')
    expect(evidence).toHaveTextContent('Transmission evidence (condition 3)')
    expect(evidence).toHaveTextContent('not_recorded')
    expect(evidence).toHaveTextContent('Enforcement mode (condition 4)')

    const verdict = screen.getByTestId('sd-event-detail-prevention')
    expect(verdict).toHaveAttribute('data-prevention', 'unmeasured')
    expect(verdict).toHaveTextContent('could not be established either way')
  })

  it('describes a blocked action’s rewrites without implying anything was delivered', () => {
    render(<EventDetailPanel detail={detail} onClose={vi.fn()} />)
    const sentence = screen.getByTestId('sd-event-detail-transformations')
    expect(sentence).toHaveTextContent(
      '2 of this action’s 3 findings were rewritten before the action was refused',
    )
    expect(sentence).toHaveTextContent('nothing reached the destination')
  })

  it('shows nothing about the action when the detail could not be read', () => {
    render(
      <EventDetailPanel
        detail={absent('unavailable', 'HTTP 404')}
        onClose={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('sd-event-detail-findings')).toBeNull()
    expect(screen.getByTestId('sd-event-detail-absent')).toHaveTextContent(
      'Nothing is inferred from the row that opened this panel',
    )
  })
})

describe('ExportPanel', () => {
  it('issues no request at all on mount', () => {
    // The export is access-logged against a principal. A page that fetched it to
    // populate a panel would write that record without anyone asking.
    render(<ExportPanel filters={DEFAULT_FILTERS} />)
    expect(getMock).not.toHaveBeenCalled()
  })

  it('does not offer the export until it has been acknowledged', () => {
    render(<ExportPanel filters={DEFAULT_FILTERS} />)
    const button = screen.getByTestId('sd-export-run')
    expect(button).toBeDisabled()

    fireEvent.click(screen.getByTestId('sd-export-ack'))
    expect(button).toBeEnabled()
    // Still nothing fetched — ticking the box is consent, not the act.
    expect(getMock).not.toHaveBeenCalled()
  })

  it('sends the acknowledgement the operator actually gave', async () => {
    getMock.mockResolvedValue({
      data: {
        scope: SCOPE,
        access_record: {
          at: '2026-08-07T14:00:00Z',
          principal: 'key-7f',
          org_id: 'acme',
          tenant_id: 'acme',
          from_ns: SCOPE.from_ns,
          to_ns: SCOPE.to_ns,
          event_count: 12,
          finding_count: 37,
        },
      },
      error: undefined,
      response: { status: 200 },
    })

    render(<ExportPanel filters={DEFAULT_FILTERS} />)
    fireEvent.click(screen.getByTestId('sd-export-ack'))
    fireEvent.click(screen.getByTestId('sd-export-run'))

    await waitFor(() => expect(getMock).toHaveBeenCalledTimes(1))
    expect(getMock.mock.calls[0][0]).toBe('/api/v1/sensitive-data/export')
    expect(getMock.mock.calls[0][1].params.query.acknowledge_export).toBe(true)
  })

  it('reports what was released from the gateway’s own access record', async () => {
    getMock.mockResolvedValue({
      data: {
        scope: SCOPE,
        access_record: {
          at: '2026-08-07T14:00:00Z',
          principal: 'key-7f',
          org_id: 'acme',
          tenant_id: 'acme',
          from_ns: SCOPE.from_ns,
          to_ns: SCOPE.to_ns,
          event_count: 12,
          finding_count: 37,
        },
      },
      error: undefined,
      response: { status: 200 },
    })

    render(<ExportPanel filters={DEFAULT_FILTERS} />)
    fireEvent.click(screen.getByTestId('sd-export-ack'))
    fireEvent.click(screen.getByTestId('sd-export-run'))

    const result = await screen.findByTestId('sd-export-result')
    // Both units, from the record the audit log holds — not from array lengths,
    // which could disagree with it.
    expect(result).toHaveTextContent('Exported 12 actions and 37 findings')
    expect(result).toHaveTextContent('recorded against key-7f')
  })

  it('says the export could not be summarised rather than summarising it optimistically', async () => {
    getMock.mockResolvedValue({
      data: { scope: SCOPE },
      error: undefined,
      response: { status: 200 },
    })

    render(<ExportPanel filters={DEFAULT_FILTERS} />)
    fireEvent.click(screen.getByTestId('sd-export-ack'))
    fireEvent.click(screen.getByTestId('sd-export-run'))

    const result = await screen.findByTestId('sd-export-result')
    expect(result).toHaveTextContent('its access record could not be read')
    expect(result.textContent).not.toMatch(/Exported \d/)
  })

  it('renders a refusal as a refusal, not as an empty export', async () => {
    getMock.mockResolvedValue({
      data: undefined,
      error: { title: 'forbidden' },
      response: { status: 403 },
    })

    render(<ExportPanel filters={DEFAULT_FILTERS} />)
    fireEvent.click(screen.getByTestId('sd-export-ack'))
    fireEvent.click(screen.getByTestId('sd-export-run'))

    const refused = await screen.findByTestId('sd-export-refused-state')
    expect(refused).toHaveTextContent('You cannot view this organisation’s sensitive-data records')
    expect(refused).toHaveTextContent('an empty page here would be a claim, and this is a refusal')
    expect(screen.queryByTestId('sd-export-result')).toBeNull()
  })
})
