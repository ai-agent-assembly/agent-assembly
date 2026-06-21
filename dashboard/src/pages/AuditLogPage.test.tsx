import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../api/client'
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
      <MemoryRouter initialEntries={['/audit']}>
        <AuditLogPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  get.mockResolvedValue({ data: ENTRIES })
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
})
