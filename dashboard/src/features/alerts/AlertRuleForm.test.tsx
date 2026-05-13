import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AlertRuleForm } from './AlertRuleForm'
import { ToastProvider } from '../../components/ToastProvider'
import type { AlertRule, Destination } from './types'

// ── fetch stub mirroring the AAASM-1075 test setup ─────────────────────────

interface FetchCall {
  url: string
  init: RequestInit
}

let calls: FetchCall[]
/** Map URL prefix → response body. Set per-test in `beforeEach`. */
let responses: Record<string, unknown>

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
          return {
            ok: true,
            status: init.method === 'POST' ? 201 : 200,
            json: async () => responses[prefix],
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

// ── fixtures ───────────────────────────────────────────────────────────────

const SLACK: Destination = {
  id: 'd-slack',
  kind: 'slack',
  name: 'ops',
  enabled: true,
  createdAt: '2026-05-13T00:00:00Z',
  updatedAt: '2026-05-13T00:00:00Z',
  config: { webhookUrl: 'https://hooks.slack.com/services/x' },
}

const FIXTURE_RULE: AlertRule = {
  id: 'r-1',
  name: 'Budget > 90%',
  description: '',
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

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}

// ── specs ──────────────────────────────────────────────────────────────────

describe('AlertRuleForm', () => {
  it('does not render anything when closed', () => {
    render(<AlertRuleForm open={false} onClose={vi.fn()} />, { wrapper: Wrapper })
    expect(screen.queryByTestId('alert-rule-form')).not.toBeInTheDocument()
  })

  it('renders the create heading when no initialValue is supplied', async () => {
    responses['/api/v1/alerts/destinations'] = [SLACK]
    render(<AlertRuleForm open={true} onClose={vi.fn()} />, { wrapper: Wrapper })
    expect(
      screen.getByRole('heading', { name: 'New alert rule' }),
    ).toBeInTheDocument()
  })

  it('blocks submit when the threshold is missing (zod required)', async () => {
    responses['/api/v1/alerts/destinations'] = [SLACK]
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<AlertRuleForm open={true} onClose={onClose} />, { wrapper: Wrapper })

    await waitFor(() =>
      expect(screen.getByTestId('rule-destination-d-slack')).toBeInTheDocument(),
    )
    await user.click(screen.getByTestId('rule-destination-d-slack'))
    await user.type(screen.getByTestId('rule-name'), 'Budget guardrail')
    await user.clear(screen.getByTestId('rule-threshold'))
    await user.click(screen.getByTestId('alert-rule-form-submit'))

    await waitFor(() =>
      expect(screen.getByText(/threshold must be (a number|a finite number)/i)).toBeInTheDocument(),
    )
    expect(onClose).not.toHaveBeenCalled()
    expect(calls.some((c) => c.init.method === 'POST' && c.url.endsWith('/rules'))).toBe(false)
  })

  it('blocks submit when no destination is selected', async () => {
    responses['/api/v1/alerts/destinations'] = [SLACK]
    const user = userEvent.setup()
    render(<AlertRuleForm open={true} onClose={vi.fn()} />, { wrapper: Wrapper })
    await user.type(screen.getByTestId('rule-name'), 'Budget guardrail')
    await user.click(screen.getByTestId('alert-rule-form-submit'))
    await waitFor(() =>
      expect(
        screen.getByText(/at least one destination is required/i),
      ).toBeInTheDocument(),
    )
  })

  it('POSTs to /alerts/rules on a valid create submit and closes the modal', async () => {
    responses['/api/v1/alerts/destinations'] = [SLACK]
    responses['/api/v1/alerts/rules'] = FIXTURE_RULE
    const user = userEvent.setup()
    const onClose = vi.fn()
    const onSaved = vi.fn()
    render(
      <AlertRuleForm open={true} onClose={onClose} onSaved={onSaved} />,
      { wrapper: Wrapper },
    )

    await waitFor(() =>
      expect(screen.getByTestId('rule-destination-d-slack')).toBeInTheDocument(),
    )
    await user.type(screen.getByTestId('rule-name'), 'Budget guardrail')
    await user.click(screen.getByTestId('rule-destination-d-slack'))
    await user.click(screen.getByTestId('alert-rule-form-submit'))

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
    expect(onSaved).toHaveBeenCalledWith(FIXTURE_RULE)
    const post = calls.find((c) => c.init.method === 'POST' && c.url.endsWith('/rules'))
    expect(post).toBeDefined()
    const body = JSON.parse(post!.init.body as string)
    expect(body.name).toBe('Budget guardrail')
    expect(body.destinationIds).toEqual(['d-slack'])
  })

  it('PUTs to /alerts/rules/{id} when initialValue is supplied', async () => {
    responses['/api/v1/alerts/destinations'] = [SLACK]
    responses[`/api/v1/alerts/rules/${FIXTURE_RULE.id}`] = FIXTURE_RULE
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(
      <AlertRuleForm open={true} onClose={onClose} initialValue={FIXTURE_RULE} />,
      { wrapper: Wrapper },
    )

    expect(
      screen.getByRole('heading', { name: 'Edit alert rule' }),
    ).toBeInTheDocument()

    await user.click(screen.getByTestId('alert-rule-form-submit'))
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
    const put = calls.find((c) => c.init.method === 'PUT')
    expect(put).toBeDefined()
    expect(put!.url).toContain(`/rules/${FIXTURE_RULE.id}`)
  })

  it('shows an error toast and keeps the modal open when the API call fails', async () => {
    responses['/api/v1/alerts/destinations'] = [SLACK]
    // /rules deliberately unstubbed → falls through to 500
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<AlertRuleForm open={true} onClose={onClose} />, { wrapper: Wrapper })

    await waitFor(() =>
      expect(screen.getByTestId('rule-destination-d-slack')).toBeInTheDocument(),
    )
    await user.type(screen.getByTestId('rule-name'), 'Budget guardrail')
    await user.click(screen.getByTestId('rule-destination-d-slack'))
    await user.click(screen.getByTestId('alert-rule-form-submit'))

    // Error toast is rendered by the global ToastProvider — the wrapper is
    // mounted above the form, so the toast region appears in the DOM tree.
    await waitFor(() =>
      expect(within(document.body).getByText(/POST .* failed: 500/i)).toBeInTheDocument(),
    )
    expect(onClose).not.toHaveBeenCalled()
  })
})
