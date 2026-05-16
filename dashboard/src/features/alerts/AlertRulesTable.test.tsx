import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AlertRulesTable } from './AlertRulesTable'
import { ToastProvider } from '../../components/ToastProvider'
import type { AlertRule } from './types'

// fetch-stub pattern reused from AlertRuleForm.test.tsx (AAASM-1077).

interface FetchCall {
  url: string
  init: RequestInit
}

let calls: FetchCall[]
let responses: Record<string, { status?: number; body: unknown }>

beforeEach(() => {
  calls = []
  responses = {}
  localStorage.setItem('aa_token', 'test-token')
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init })
      for (const prefix of Object.keys(responses)) {
        if (url.startsWith(prefix)) {
          const { status, body } = responses[prefix]
          return {
            ok: !status || status < 400,
            status: status ?? 200,
            json: async () => body,
          } as Response
        }
      }
      return {
        ok: false,
        status: 500,
        json: async () => ({ error: 'no stub for ' + url }),
      } as Response
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
})

const RULE_A: AlertRule = {
  id: 'r-a',
  name: 'Budget > 90%',
  description: 'Warn when daily spend exceeds 90% of cap',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 90,
  evaluationWindowSeconds: 300,
  severity: 'CRITICAL',
  destinationIds: ['d-slack'],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '2026-05-13T00:00:00Z',
  updatedAt: '2026-05-13T00:00:00Z',
}

const RULE_B: AlertRule = {
  ...RULE_A,
  id: 'r-b',
  name: 'Policy violations > 5',
  description: '',
  metric: 'policy_violations_count',
  threshold: 5,
  severity: 'HIGH',
  enabled: false,
}

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}

describe('AlertRulesTable', () => {
  it('renders one row per rule with name, metric, condition, severity badge, status', async () => {
    responses['/api/v1/alerts/rules'] = { body: [RULE_A, RULE_B] }
    render(
      <AlertRulesTable
        onCreate={vi.fn()}
        onEdit={vi.fn()}
        onOpenDestinations={vi.fn()}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() => expect(screen.getByTestId('alert-rules-table')).toBeInTheDocument())
    const rows = screen.getAllByTestId('alert-rules-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveAttribute('data-rule-id', 'r-a')
    expect(rows[0]).toHaveTextContent('Budget > 90%')
    expect(rows[0]).toHaveTextContent('budget_spent_pct')
    expect(rows[0]).toHaveTextContent('> 90')
    expect(rows[0]).toHaveTextContent('enabled')

    expect(rows[1]).toHaveAttribute('data-rule-id', 'r-b')
    expect(rows[1]).toHaveTextContent('Policy violations > 5')
    expect(rows[1]).toHaveTextContent('disabled')

    // Severity badges render as their AAASM-1395-locked-in tokens.
    expect(screen.getByTestId('severity-badge-CRITICAL')).toBeInTheDocument()
    expect(screen.getByTestId('severity-badge-HIGH')).toBeInTheDocument()
  })

  it('renders EmptyStateNoRules when the rules query returns an empty list', async () => {
    responses['/api/v1/alerts/rules'] = { body: [] }
    const onCreate = vi.fn()
    render(
      <AlertRulesTable
        onCreate={onCreate}
        onEdit={vi.fn()}
        onOpenDestinations={vi.fn()}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() =>
      expect(screen.getByTestId('alerts-empty-no-rules')).toBeInTheDocument(),
    )
    // The shared empty-state CTA opens the rule form in create mode.
    await userEvent.click(screen.getByTestId('alerts-empty-create-cta'))
    expect(onCreate).toHaveBeenCalledOnce()
  })

  it('toolbar "+ New rule" fires onCreate; "Add destination" fires onOpenDestinations', async () => {
    responses['/api/v1/alerts/rules'] = { body: [RULE_A] }
    const onCreate = vi.fn()
    const onOpenDestinations = vi.fn()
    render(
      <AlertRulesTable
        onCreate={onCreate}
        onEdit={vi.fn()}
        onOpenDestinations={onOpenDestinations}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() => screen.getByTestId('alert-rules-table'))
    await userEvent.click(screen.getByTestId('alert-rules-create'))
    expect(onCreate).toHaveBeenCalledOnce()

    await userEvent.click(screen.getByTestId('alert-rules-open-destinations'))
    expect(onOpenDestinations).toHaveBeenCalledOnce()
  })

  it('Edit on a row fires onEdit with that rule', async () => {
    responses['/api/v1/alerts/rules'] = { body: [RULE_A, RULE_B] }
    const onEdit = vi.fn()
    render(
      <AlertRulesTable
        onCreate={vi.fn()}
        onEdit={onEdit}
        onOpenDestinations={vi.fn()}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() => screen.getByTestId('alert-rules-table'))
    const editButtons = screen.getAllByTestId('alert-rules-row-edit')
    expect(editButtons).toHaveLength(2)
    await userEvent.click(editButtons[1])
    expect(onEdit).toHaveBeenCalledWith(RULE_B)
  })

  it('Delete on a row fires the delete mutation and surfaces a success toast', async () => {
    responses['/api/v1/alerts/rules'] = { body: [RULE_A] }
    // DELETE returns 204; mutation onSuccess will toast.
    responses['/api/v1/alerts/rules/r-a'] = { status: 204, body: null }

    render(
      <AlertRulesTable
        onCreate={vi.fn()}
        onEdit={vi.fn()}
        onOpenDestinations={vi.fn()}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() => screen.getByTestId('alert-rules-table'))
    await userEvent.click(screen.getByTestId('alert-rules-row-delete'))

    // The DELETE fetch fires against the canonical endpoint.
    await waitFor(() => {
      const deletes = calls.filter((c) => c.init.method === 'DELETE')
      expect(deletes).toHaveLength(1)
      expect(deletes[0].url).toContain('/api/v1/alerts/rules/r-a')
    })

    // Success toast surfaces the rule name.
    await waitFor(() => {
      expect(screen.getByText(/Deleted rule/)).toBeInTheDocument()
    })
  })

  it('shows the error banner when the rules query fails', async () => {
    responses['/api/v1/alerts/rules'] = { status: 500, body: { error: 'boom' } }
    render(
      <AlertRulesTable
        onCreate={vi.fn()}
        onEdit={vi.fn()}
        onOpenDestinations={vi.fn()}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() => expect(screen.getByTestId('alert-rules-error')).toBeInTheDocument())
  })
})
