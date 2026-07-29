import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../api/client'
import { ToastProvider } from '../components/ToastProvider'
import { AuditLogPage } from './AuditLogPage'
import { AUDIT_PAGE_SIZE, type LogEntry } from '../features/audit/logs'

const RESEARCH_AGENT = '9f2c1a7b4d8e0f3a6b5c4d3e2f1a0b9c'
const SUPPORT_AGENT = '00112233445566778899aabbccddeeff'

function entry(partial: Partial<LogEntry> & Pick<LogEntry, 'seq' | 'event_type'>): LogEntry {
  return {
    timestamp: '2026-05-11T14:02:11Z',
    agent_id: RESEARCH_AGENT,
    session_id: 'sess-9a4f',
    payload: '{}',
    ...partial,
  }
}

/**
 * Fixtures in the shape the gateway and runtime actually put on the wire: a
 * proto `Decision` **integer**, real `AuditEventType` variant names, and either
 * the gateway's `reason`/`policy_rule` pair or the runtime's `detail` object.
 * The previous fixtures used the hi-fi mock's invented schema, which is why the
 * suite stayed green while the shipped page rendered blank columns.
 */
const ENTRIES: LogEntry[] = [
  entry({
    seq: 1048,
    event_type: 'PolicyViolation',
    timestamp: '2026-05-11T14:02:11Z',
    payload: JSON.stringify({
      action_type: 2,
      decision: 2,
      reason: 'External recipient requires explicit approval',
      policy_rule: 'deny-external-mail',
      trace_id: 'trace-abc123',
    }),
  }),
  entry({
    seq: 1047,
    event_type: 'ToolCallIntercepted',
    timestamp: '2026-05-11T14:01:58Z',
    payload: JSON.stringify({
      action_type: 'TOOL_CALL',
      decision: 1,
      source: 'sdk',
      detail: { kind: 'tool_call', tool_name: 'pg_users', tool_source: 'mcp', succeeded: true },
    }),
  }),
  entry({
    seq: 1044,
    event_type: 'ApprovalGranted',
    agent_id: SUPPORT_AGENT,
    session_id: 'sess-6d44',
    timestamp: '2026-05-11T14:01:09Z',
    payload: JSON.stringify({
      decision: 1,
      detail: { kind: 'approval', approval_id: 'zendesk-escalation', approved: true },
    }),
  }),
]

let get: Mock

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/audit']}>
          <AuditLogPage />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

/** `/logs` returns a paginated `{ items, page, per_page, total }` envelope. */
function page(items: LogEntry[], total = items.length, pageNumber = 1) {
  return { items, page: pageNumber, per_page: AUDIT_PAGE_SIZE, total }
}

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  get.mockResolvedValue({ data: page(ENTRIES) })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('AuditLogPage', () => {
  it('queries /api/v1/logs with explicit pagination', async () => {
    renderPage()
    await screen.findByTestId('audit-table')
    expect(get).toHaveBeenCalledWith('/api/v1/logs', {
      params: { query: { page: 1, per_page: AUDIT_PAGE_SIZE } },
    })
  })

  it('renders a row for every audit entry', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    expect(screen.getByTestId('audit-row-1047')).toBeInTheDocument()
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('3 / 3')
  })

  // ── AAASM-5117: the regression this lane exists to prevent ────────────────
  it('renders the decision verdict from the integer wire form', async () => {
    renderPage()
    const denied = await screen.findByTestId('audit-row-1048')
    expect(within(denied).getByTestId('audit-decision-1048')).toHaveTextContent('deny')
    const allowed = screen.getByTestId('audit-row-1047')
    expect(within(allowed).getByTestId('audit-decision-1047')).toHaveTextContent('allow')
  })

  it.each([
    [1, 'allow'],
    [2, 'deny'],
    [3, 'pending'],
    [4, 'redact'],
  ])('maps proto discriminant %i to the %s chip', async (discriminant, label) => {
    get.mockResolvedValue({
      data: page([entry({ seq: 700, event_type: 'ToolCallIntercepted', payload: `{"decision":${discriminant}}` })]),
    })
    renderPage()
    const cell = await screen.findByTestId('audit-decision-700')
    expect(cell).toHaveTextContent(label)
    expect(cell).toHaveAttribute('data-testid', 'audit-decision-700')
  })

  it('renders the real event-type chip label', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')
    expect(within(row).getByText(/Policy Violation/)).toBeInTheDocument()
    expect(within(screen.getByTestId('audit-row-1047')).getByText(/Tool Call/)).toBeInTheDocument()
  })

  it('shows an event-detail cross-link per row at /audit/event/:seq', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    expect(screen.getByTestId('audit-event-link-1048')).toHaveAttribute(
      'href',
      '/audit/event/1048',
    )
  })

  // ── AAASM-5118: the stats strip and filters count real variants ───────────
  it('offers only real event families in the type filter', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    for (const invented of ['LLMCall', 'ToolCall', 'FileOp', 'NetworkCall', 'ApprovalEvent']) {
      expect(screen.queryByTestId(`audit-type-btn-${invented}`)).toBeNull()
      expect(screen.queryByTestId(`audit-stat-${invented}`)).toBeNull()
    }
    expect(screen.getByTestId('audit-type-btn-policy')).toBeInTheDocument()
    expect(screen.getByTestId('audit-type-btn-approval')).toBeInTheDocument()
    expect(screen.getByTestId('audit-type-btn-sandbox')).toBeInTheDocument()
  })

  it('counts real variants into their family tile', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    expect(screen.getByTestId('audit-stat-policy')).toHaveTextContent('1')
    expect(screen.getByTestId('audit-stat-tool')).toHaveTextContent('1')
    expect(screen.getByTestId('audit-stat-approval')).toHaveTextContent('1')
  })

  it('routes an unrecognised event type into the Unrecognised tile', async () => {
    get.mockResolvedValue({
      // A variant outside the closed `LogEventType` enum — deliberately cast to
      // exercise the UI's runtime fallback for a value a future backend could
      // emit before the generated schema catches up (the "Unrecognised" tile).
      data: page([
        entry({ seq: 901, event_type: 'SomeFutureVariant' as LogEntry['event_type'], payload: '{}' }),
      ]),
    })
    renderPage()
    const row = await screen.findByTestId('audit-row-901')
    expect(within(row).getByText(/SomeFutureVariant/)).toBeInTheDocument()
    expect(screen.getByTestId('audit-stat-other')).toHaveTextContent('1')
  })

  // ── AAASM-5234: event_type is raw wire (`type: string`), so a value that
  // collides with a prototype member (`constructor`, `__proto__`) must fall to
  // the default meta, not resolve to an inherited object member. A plain-object
  // lookup with `?? default` fails this because the inherited member is truthy;
  // keying by Map makes the lookup own-keys only.
  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty'])(
    'falls to the default meta for the prototype-member event type %s',
    async (inherited) => {
      get.mockResolvedValue({
        data: page([entry({ seq: 950, event_type: inherited as never, payload: '{}' })]),
      })
      renderPage()
      const row = await screen.findByTestId('audit-row-950')
      // The default meta labels the chip with the raw event type verbatim; a
      // leaked inherited member would render `[object Object]`/`function ...`.
      expect(within(row).getByText(new RegExp(inherited))).toBeInTheDocument()
      const chip = within(row).getByText(new RegExp(inherited))
      expect(chip.textContent).not.toContain('[object')
      expect(chip.textContent).not.toContain('function')
      expect(screen.getByTestId('audit-stat-other')).toHaveTextContent('1')
    },
  )

  it('still maps a real event type to its declared meta', async () => {
    get.mockResolvedValue({
      data: page([entry({ seq: 951, event_type: 'PolicyViolation', payload: '{}' })]),
    })
    renderPage()
    const row = await screen.findByTestId('audit-row-951')
    expect(within(row).getByText(/Policy Violation/)).toBeInTheDocument()
    expect(within(row).getByText(/⚑/)).toBeInTheDocument()
  })

  it('filters by event family when a stats tile is clicked', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-stat-tool'))

    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())
    expect(screen.getByTestId('audit-row-1047')).toBeInTheDocument()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('1 / 3')
  })

  it('filters by event family via the type-filter button row', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-type-btn-approval'))

    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
    expect(screen.getByTestId('audit-type-btn-approval')).toHaveAttribute('aria-pressed', 'true')
  })

  it('resets to all families via the "all" type-filter button', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-type-btn-approval'))
    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())

    fireEvent.click(screen.getByTestId('audit-type-btn-all'))
    await waitFor(() => {
      expect(screen.getByTestId('audit-count')).toHaveTextContent('3 / 3')
    })
  })

  // ── AAASM-5119: no more `undefined — undefined`, no more JSON dumps ───────
  it('summarises a gateway policy violation from reason and policy_rule', async () => {
    renderPage()
    const summary = await screen.findByTestId('audit-summary-1048')
    expect(summary).toHaveTextContent(
      'External recipient requires explicit approval — deny-external-mail',
    )
    expect(summary.textContent).not.toContain('undefined')
  })

  it('summarises a runtime detail object', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1047')
    expect(screen.getByTestId('audit-summary-1047')).toHaveTextContent('pg_users (mcp)')
  })

  it('renders an explicit absence rather than a raw JSON dump', async () => {
    get.mockResolvedValue({
      data: page([entry({ seq: 903, event_type: 'SandboxStarted', payload: '{"event_id":"e"}' })]),
    })
    renderPage()
    const summary = await screen.findByTestId('audit-summary-903')
    expect(summary).toHaveAttribute('data-truth-state', 'unknown')
    expect(summary.textContent).not.toContain('event_id')
  })

  it('renders an absence marker when the payload carries no verdict', async () => {
    get.mockResolvedValue({
      data: page([entry({ seq: 900, event_type: 'SandboxStarted', payload: '{"event_id":"e"}' })]),
    })
    renderPage()
    const cell = await screen.findByTestId('audit-decision-900')
    expect(cell).toHaveAttribute('data-truth-state', 'not-evaluated')
  })

  // ── AAASM-5151: the id is a digest, and the page says so ──────────────────
  it('labels the agent column as an audit id digest and does not link it', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')
    const id = within(row).getByTestId('audit-agent-id-1048')
    expect(id).toHaveAttribute('title', expect.stringContaining(RESEARCH_AGENT))
    expect(id).toHaveAttribute('title', expect.stringContaining('not resolvable'))
    // Nothing offers navigation to an agent page the digest cannot resolve.
    expect(within(row).queryByTestId('audit-agent-link-1048')).toBeNull()
  })

  it('shows the full digest in the expanded metadata', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')
    fireEvent.click(row)
    expect(await screen.findByTestId('audit-agent-full-1048')).toHaveTextContent(RESEARCH_AGENT)
  })

  it('lists one agent-select option per distinct digest plus "all"', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    const options = within(screen.getByTestId('audit-agent-filter')).getAllByRole('option')
    expect(options.map((o) => o.getAttribute('value'))).toEqual([
      'all',
      RESEARCH_AGENT,
      SUPPORT_AGENT,
    ])
    // The full digest stays available even though the label is shortened.
    expect(options[1]).toHaveAttribute('title', RESEARCH_AGENT)
  })

  it('filters by agent via the agent select', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-agent-filter'), {
      target: { value: SUPPORT_AGENT },
    })

    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
  })

  it('filters by free-text search across agent / summary / session', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-search'), { target: { value: 'pg_users' } })

    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())
    expect(screen.getByTestId('audit-row-1047')).toBeInTheDocument()
  })

  it('combines the type filter with free-text search', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-type-btn-tool'))
    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())

    fireEvent.change(screen.getByTestId('audit-search'), { target: { value: 'no-match' } })
    expect(await screen.findByTestId('audit-empty')).toBeInTheDocument()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('0 / 3')
  })

  it('expands a row to reveal the payload detail', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')

    expect(screen.queryByTestId('audit-detail-1048')).toBeNull()
    fireEvent.click(row)

    const detail = await screen.findByTestId('audit-detail-1048')
    expect(within(detail).getByText(/deny-external-mail/)).toBeInTheDocument()
  })

  it('labels the timestamp cell with the UTC zone', async () => {
    // The wire timestamp is UTC; on a compliance surface the zone must be
    // explicit so a clock time is not read as local (AAASM-5172).
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')
    expect(within(row).getByText('14:02:11 UTC')).toBeInTheDocument()
  })

  it('shows a ▼/▲ expand glyph that mirrors the row state', async () => {
    // The disclosure glyph from the mock (design/v1/hi-fi/audit-log.jsx) sits
    // beside the View link and flips with the row (AAASM-5172).
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')
    const glyph = screen.getByTestId('audit-expand-glyph-1048')

    expect(glyph).toHaveTextContent('▼')
    fireEvent.click(row)
    expect(screen.getByTestId('audit-expand-glyph-1048')).toHaveTextContent('▲')
  })

  it('shows the trace id in the expanded metadata when the payload carries one', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('audit-row-1048'))
    const detail = await screen.findByTestId('audit-detail-1048')
    expect(within(detail).getByTestId('audit-trace-1048')).toHaveTextContent('trace-abc123')
  })

  it('renders an absence marker for a row with no trace id', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('audit-row-1047'))
    const trace = await screen.findByTestId('audit-trace-1047')
    expect(trace).toHaveAttribute('data-truth-state', 'unknown')
  })

  it('shows the empty state when no entries match the filter', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-search'), {
      target: { value: 'no-such-entry-xyz' },
    })

    expect(await screen.findByTestId('audit-empty')).toBeInTheDocument()
  })

  it('renders an unavailable state with a retry control when the query fails', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } })
    renderPage()
    const state = await screen.findByTestId('audit-error')
    expect(state).toHaveAttribute('data-truth-state', 'unavailable')
    // The failure must not read as an empty trail.
    expect(state).toHaveTextContent('this is not an empty trail')
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('re-reads the trail when Retry is pressed after a failure', async () => {
    get.mockResolvedValueOnce({ error: { message: 'boom' } })
    renderPage()
    await screen.findByTestId('audit-error')

    get.mockResolvedValue({ data: page(ENTRIES) })
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    expect(await screen.findByTestId('audit-row-1048')).toBeInTheDocument()
  })

  it('opens the event detail link without also expanding the row', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-event-link-1048'))

    expect(screen.queryByTestId('audit-detail-1048')).toBeNull()
  })

  it('shows the loading state before the query resolves', async () => {
    let resolve: (v: { data: ReturnType<typeof page> }) => void = () => {}
    get.mockReturnValue(
      new Promise<{ data: ReturnType<typeof page> }>((r) => {
        resolve = r
      }),
    )
    renderPage()
    expect(await screen.findByTestId('audit-loading')).toBeInTheDocument()
    resolve({ data: page(ENTRIES) })
    await screen.findByTestId('audit-table')
  })
})

// ── AAASM-5120 ─────────────────────────────────────────────────────────────
describe('AuditLogPage — window coverage', () => {
  function fullPage(pageNumber: number, total: number): { data: ReturnType<typeof page> } {
    const items = Array.from(
      { length: AUDIT_PAGE_SIZE },
      (_, i): LogEntry => ({
        seq: (pageNumber - 1) * AUDIT_PAGE_SIZE + i,
        timestamp: '2026-05-11T14:02:11Z',
        agent_id: RESEARCH_AGENT,
        session_id: 'sess-9a4f',
        event_type: 'ToolCallIntercepted',
        payload: '{"decision":1}',
      }),
    )
    return { data: page(items, total, pageNumber) }
  }

  it('states plainly that a short window is not the complete trail', async () => {
    get.mockResolvedValue(fullPage(1, 4820))
    renderPage()
    const banner = await screen.findByTestId('audit-coverage')
    expect(banner).toHaveTextContent('Partial — 100 of 4820')
    expect(banner).toHaveTextContent('not the complete trail')
    expect(banner).not.toHaveTextContent('Complete')
  })

  it('confirms completeness only when the whole filtered set is loaded', async () => {
    renderPage()
    const banner = await screen.findByTestId('audit-coverage')
    expect(banner).toHaveTextContent('Complete — all 3 entries')
    expect(screen.queryByTestId('audit-load-more')).toBeNull()
  })

  it('offers a load-more control that deepens the window', async () => {
    get.mockResolvedValueOnce(fullPage(1, 250))
    get.mockResolvedValueOnce(fullPage(1, 250))
    get.mockResolvedValueOnce(fullPage(2, 250))
    renderPage()

    const more = await screen.findByTestId('audit-load-more')
    fireEvent.click(more)

    await waitFor(() =>
      expect(screen.getByTestId('audit-coverage')).toHaveTextContent('Partial — 200 of 250'),
    )
  })

  it('says so when the gateway reported no total, instead of implying completeness', async () => {
    get.mockResolvedValue({ data: { items: ENTRIES, page: 1, per_page: AUDIT_PAGE_SIZE } })
    renderPage()
    const banner = await screen.findByTestId('audit-coverage')
    expect(banner).toHaveTextContent('Coverage unknown')
    expect(banner).toHaveTextContent('may not be the complete trail')
  })

  it('marks a CSV export of a short window as partial in the toast', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    get.mockResolvedValue(fullPage(1, 4820))
    renderPage()
    await screen.findByTestId('audit-coverage')

    fireEvent.click(screen.getByTestId('audit-export-csv'))
    expect(await screen.findByTestId('toast')).toHaveTextContent('partial window')
  })

  it('marks a compliance report of a short window as partial in the toast', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:report')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    get.mockResolvedValue(fullPage(1, 4820))
    renderPage()
    await screen.findByTestId('audit-coverage')

    fireEvent.click(screen.getByTestId('audit-compliance-report'))
    expect(await screen.findByTestId('toast')).toHaveTextContent('PARTIAL window')
  })

  it('exports the filtered rows to CSV via the header action', async () => {
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-export-csv'))

    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect((createSpy.mock.calls[0][0] as Blob).type).toContain('text/csv')
  })

  it('warns and skips the download when the CSV export has no rows in scope', async () => {
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit')

    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-search'), {
      target: { value: 'no-such-entry-xyz' },
    })
    await screen.findByTestId('audit-empty')

    fireEvent.click(screen.getByTestId('audit-export-csv'))

    expect(await screen.findByTestId('toast')).toHaveTextContent('No rows to export')
    expect(createSpy).not.toHaveBeenCalled()
  })

  it('uses singular wording when exactly one row is exported', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-type-btn-approval'))
    await waitFor(() => expect(screen.getByTestId('audit-count')).toHaveTextContent('1 / 3'))

    fireEvent.click(screen.getByTestId('audit-export-csv'))
    expect(await screen.findByTestId('toast')).toHaveTextContent('Exported 1 row to CSV')
  })

  it('generates a compliance report via the header action', async () => {
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:report')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-compliance-report'))

    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(clickSpy).toHaveBeenCalledTimes(1)
  })
})

// ── AAASM-5117 review blocker: observe mode ────────────────────────────────
describe('AuditLogPage — observe mode', () => {
  // Exactly what a suppressed denial looks like on the wire: the decision is
  // rewritten to ALLOW (1), the event type is rewritten to the benign
  // ToolCallIntercepted, `reason`/`policy_rule` are emptied, and only the
  // shadow fields record that anything was blocked.
  const SUPPRESSED = entry({
    seq: 2001,
    event_type: 'ToolCallIntercepted',
    payload: JSON.stringify({
      action_type: 2,
      decision: 1,
      reason: '',
      policy_rule: '',
      dry_run: true,
      shadow_decision: 'deny',
      shadow_reason: 'gmail/send blocked for external recipients',
    }),
  })

  beforeEach(() => {
    get.mockResolvedValue({ data: page([SUPPRESSED]) })
  })

  it('never renders a suppressed denial as a bare allow', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-2001')
    // The enforced allow is still shown — the action did proceed...
    expect(within(row).getByTestId('audit-decision-2001')).toHaveTextContent('allow')
    // ...but the suppressed denial is on screen beside it.
    const marker = within(row).getByTestId('audit-suppressed-2001')
    expect(marker).toHaveTextContent('observe: deny')
    expect(marker).toHaveAttribute(
      'title',
      expect.stringContaining('gmail/send blocked for external recipients'),
    )
  })

  it('scans as a violation row despite the rewritten event type', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-2001')
    expect(row.className).toContain('audit-row--violation')
  })

  it('recovers the suppressed reason into the summary column', async () => {
    renderPage()
    await screen.findByTestId('audit-row-2001')
    expect(screen.getByTestId('audit-summary-2001')).toHaveTextContent(
      'gmail/send blocked for external recipients',
    )
  })

  it('shows the suppression in the expanded detail too', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('audit-row-2001'))
    await screen.findByTestId('audit-detail-2001')
    expect(screen.getByTestId('audit-suppressed--2001')).toHaveTextContent('observe: deny')
  })

  it('does not mark an ordinary enforce-mode allow as suppressed', async () => {
    get.mockResolvedValue({ data: page(ENTRIES) })
    renderPage()
    await screen.findByTestId('audit-row-1047')
    expect(screen.queryByTestId('audit-suppressed-1047')).toBeNull()
  })
})
