import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../api/client'
import { ToastProvider } from '../components/ToastProvider'
import { AuditLogPage } from './AuditLogPage'
import type { LogEntry } from '../features/audit/logs'

function entry(partial: Partial<LogEntry> & Pick<LogEntry, 'seq' | 'event_type'>): LogEntry {
  return {
    timestamp: '2026-05-11T14:02:11Z',
    agent_id: 'research-bot-04',
    session_id: 'sess-9a4f',
    payload: '{}',
    ...partial,
  }
}

const ENTRIES: LogEntry[] = [
  entry({
    seq: 1048,
    event_type: 'PolicyViolation',
    agent_id: 'research-bot-04',
    session_id: 'sess-9a4f',
    timestamp: '2026-05-11T14:02:11Z',
    payload: JSON.stringify({
      decision: 'DENY',
      blocked_action: 'gmail/send → ext@vendor.com',
      reason: 'External recipient requires explicit approval',
    }),
  }),
  entry({
    seq: 1047,
    event_type: 'LLMCall',
    agent_id: 'research-bot-04',
    session_id: 'sess-9a4f',
    timestamp: '2026-05-11T14:01:58Z',
    payload: JSON.stringify({
      decision: 'ALLOW',
      model: 'claude-3-5-sonnet',
      prompt_tokens: 2840,
      completion_tokens: 412,
      latency_ms: 1840,
    }),
  }),
  entry({
    seq: 1044,
    event_type: 'ToolCall',
    agent_id: 'support-triage',
    session_id: 'sess-6d44',
    timestamp: '2026-05-11T14:01:09Z',
    payload: JSON.stringify({
      decision: 'ALLOW',
      tool_name: 'zendesk_search',
      tool_source: 'mcp',
      latency_ms: 142,
      succeeded: true,
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

// AAASM-4892: /logs returns a paginated { items, total } object, not a bare array.
function page(items: LogEntry[]) {
  return { items, page: 1, per_page: 50, total: items.length }
}

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  get.mockResolvedValue({ data: page(ENTRIES) })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('AuditLogPage', () => {
  it('queries the /api/v1/logs endpoint', async () => {
    renderPage()
    await screen.findByTestId('audit-table')
    expect(get).toHaveBeenCalledWith('/api/v1/logs', { params: { query: {} } })
  })

  it('renders a row for every audit entry', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    expect(screen.getByTestId('audit-row-1047')).toBeInTheDocument()
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('3 / 3')
  })

  it('renders the decision verdict and event-type chips', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')
    expect(within(row).getByText('deny')).toBeInTheDocument()
    expect(within(row).getByText(/Policy Violation/)).toBeInTheDocument()
  })

  it('shows an event-detail cross-link per row at /audit/event/:seq', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    const link = screen.getByTestId('audit-event-link-1048')
    expect(link).toHaveAttribute('href', '/audit/event/1048')
  })

  it('filters by event type when a stats tile is clicked', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-stat-LLMCall'))

    await waitFor(() => {
      expect(screen.queryByTestId('audit-row-1048')).toBeNull()
    })
    expect(screen.getByTestId('audit-row-1047')).toBeInTheDocument()
    expect(screen.queryByTestId('audit-row-1044')).toBeNull()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('1 / 3')
  })

  it('filters by free-text search across agent / action / session', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-search'), {
      target: { value: 'zendesk' },
    })

    await waitFor(() => {
      expect(screen.queryByTestId('audit-row-1048')).toBeNull()
    })
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
  })

  it('filters by agent via the agent select', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-agent-filter'), {
      target: { value: 'support-triage' },
    })

    await waitFor(() => {
      expect(screen.queryByTestId('audit-row-1048')).toBeNull()
    })
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
  })

  it('expands a row to reveal the payload detail', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1048')

    expect(screen.queryByTestId('audit-detail-1048')).toBeNull()
    fireEvent.click(row)

    const detail = await screen.findByTestId('audit-detail-1048')
    expect(within(detail).getByText(/External recipient requires explicit approval/)).toBeInTheDocument()
  })

  it('shows the empty state when no entries match the filter', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.change(screen.getByTestId('audit-search'), {
      target: { value: 'no-such-entry-xyz' },
    })

    expect(await screen.findByTestId('audit-empty')).toBeInTheDocument()
  })

  it('renders an error state with a retry control when the query fails', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } })
    renderPage()
    expect(await screen.findByTestId('audit-error')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('renders the allow decision chip for a non-violation row', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1047')
    expect(within(row).getByText('allow')).toBeInTheDocument()
  })

  it('renders an em-dash decision chip when the payload carries no verdict', async () => {
    get.mockResolvedValue({
      data: page([entry({ seq: 900, event_type: 'LLMCall', payload: '{"model":"gpt-4o"}' })]),
    })
    renderPage()
    const row = await screen.findByTestId('audit-row-900')
    expect(within(row).getByText('—')).toBeInTheDocument()
  })

  it('falls back to the raw event-type label for an unknown type', async () => {
    get.mockResolvedValue({
      data: page([entry({ seq: 901, event_type: 'MysteryEvent', payload: '{}' })]),
    })
    renderPage()
    const row = await screen.findByTestId('audit-row-901')
    expect(within(row).getByText(/MysteryEvent/)).toBeInTheDocument()
  })

  it('lists one agent-select option per distinct agent plus "all"', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')
    const options = within(screen.getByTestId('audit-agent-filter')).getAllByRole('option')
    expect(options.map((o) => o.getAttribute('value'))).toEqual([
      'all',
      'research-bot-04',
      'support-triage',
    ])
  })

  it('combines the type filter with free-text search', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-stat-ToolCall'))
    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())

    fireEvent.change(screen.getByTestId('audit-search'), {
      target: { value: 'no-match' },
    })
    expect(await screen.findByTestId('audit-empty')).toBeInTheDocument()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('0 / 3')
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

  it('navigates to the agent detail view from the agent link', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1044')
    const agentLink = within(row).getByTestId('audit-agent-link-1044')
    expect(agentLink).toHaveTextContent('support-triage')
  })

  it('filters by event type via the type-filter button row', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-type-btn-ToolCall'))

    await waitFor(() => {
      expect(screen.queryByTestId('audit-row-1048')).toBeNull()
    })
    expect(screen.getByTestId('audit-row-1044')).toBeInTheDocument()
    expect(screen.queryByTestId('audit-row-1047')).toBeNull()
    expect(screen.getByTestId('audit-count')).toHaveTextContent('1 / 3')
    expect(screen.getByTestId('audit-type-btn-ToolCall')).toHaveAttribute('aria-pressed', 'true')
  })

  it('resets to all types via the "all" type-filter button', async () => {
    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-type-btn-ToolCall'))
    await waitFor(() => expect(screen.queryByTestId('audit-row-1048')).toBeNull())

    fireEvent.click(screen.getByTestId('audit-type-btn-all'))
    await waitFor(() => {
      expect(screen.getByTestId('audit-count')).toHaveTextContent('3 / 3')
    })
  })

  it('exports the filtered rows to CSV via the header action', async () => {
    const createSpy = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValue('blob:audit')
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {})

    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-export-csv'))

    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(clickSpy).toHaveBeenCalledTimes(1)
    const blob = createSpy.mock.calls[0][0] as Blob
    expect(blob.type).toContain('text/csv')

    createSpy.mockRestore()
    revokeSpy.mockRestore()
    clickSpy.mockRestore()
  })

  it('warns and skips the download when the CSV export has no rows in scope', async () => {
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit')

    renderPage()
    await screen.findByTestId('audit-row-1048')

    // Narrow the table to zero rows so the export short-circuits.
    fireEvent.change(screen.getByTestId('audit-search'), {
      target: { value: 'no-such-entry-xyz' },
    })
    await screen.findByTestId('audit-empty')

    fireEvent.click(screen.getByTestId('audit-export-csv'))

    expect(await screen.findByTestId('toast')).toHaveTextContent('No rows to export')
    expect(createSpy).not.toHaveBeenCalled()

    createSpy.mockRestore()
  })

  it('uses singular wording when exactly one row is exported', async () => {
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    renderPage()
    await screen.findByTestId('audit-row-1048')

    // ToolCall matches a single row (seq 1044).
    fireEvent.click(screen.getByTestId('audit-type-btn-ToolCall'))
    await waitFor(() => expect(screen.getByTestId('audit-count')).toHaveTextContent('1 / 3'))

    fireEvent.click(screen.getByTestId('audit-export-csv'))

    expect(await screen.findByTestId('toast')).toHaveTextContent('Exported 1 row to CSV')
    expect(createSpy).toHaveBeenCalledTimes(1)

    vi.restoreAllMocks()
  })

  it('generates a compliance report via the header action', async () => {
    const createSpy = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValue('blob:report')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {})

    renderPage()
    await screen.findByTestId('audit-row-1048')

    fireEvent.click(screen.getByTestId('audit-compliance-report'))

    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(clickSpy).toHaveBeenCalledTimes(1)

    vi.restoreAllMocks()
  })

  it('shows the trace id in the expanded metadata when the payload carries one', async () => {
    get.mockResolvedValue({
      data: page([
        entry({
          seq: 902,
          event_type: 'LLMCall',
          payload: JSON.stringify({ decision: 'ALLOW', trace_id: 'trace-abc123' }),
        }),
      ]),
    })
    renderPage()
    const row = await screen.findByTestId('audit-row-902')
    fireEvent.click(row)

    const detail = await screen.findByTestId('audit-detail-902')
    expect(within(detail).getByTestId('audit-trace-902')).toHaveTextContent('trace-abc123')
  })

  it('renders an em-dash trace when the payload has no trace id', async () => {
    renderPage()
    const row = await screen.findByTestId('audit-row-1047')
    fireEvent.click(row)

    const trace = await screen.findByTestId('audit-trace-1047')
    expect(trace).toHaveTextContent('—')
  })
})
