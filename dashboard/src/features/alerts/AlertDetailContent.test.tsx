import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AlertDetailContent } from './AlertDetailContent'
import { ToastProvider } from '../../components/ToastProvider'
import * as api from './api'
import type { AlertDetail, AlertRule } from './types'

function makeQuery(
  partial: Partial<UseQueryResult<AlertDetail, Error>>,
): UseQueryResult<AlertDetail, Error> {
  return partial as unknown as UseQueryResult<AlertDetail, Error>
}

const RULE: AlertRule = {
  id: 'rule-1',
  name: 'Budget burn',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 80,
  evaluationWindowSeconds: 300,
  severity: 'HIGH',
  destinationIds: ['dest-1'],
  dedupWindowSeconds: 600,
  suppressionLabels: { team: 'x' },
  enabled: true,
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

function makeDetail(patch: Partial<AlertDetail> = {}): AlertDetail {
  return {
    id: 'a-1',
    ruleId: 'rule-1',
    ruleName: 'Budget burn',
    severity: 'HIGH',
    status: 'FIRING',
    agentId: 'agent-7',
    firstFiredAt: '2026-05-14T09:00:00Z',
    resolvedAt: null,
    destinationIds: ['dest-1'],
    ruleSnapshot: RULE,
    eventPayload: { spent: 91 },
    routingLog: [],
    silence: null,
    dedupOccurrenceCount: 1,
    dedupWindowExpiresAt: null,
    ...patch,
  }
}

function renderContent() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <AlertDetailContent alertId="a-1" />
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('AlertDetailContent', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders the loading state', () => {
    vi.spyOn(api, 'useAlertQuery').mockReturnValue(
      makeQuery({ data: undefined, isLoading: true, isError: false }),
    )
    renderContent()
    expect(screen.getByTestId('alert-detail-loading')).toBeInTheDocument()
  })

  it('renders the error state with the error message', () => {
    vi.spyOn(api, 'useAlertQuery').mockReturnValue(
      makeQuery({
        data: undefined,
        isLoading: false,
        isError: true,
        error: new Error('boom'),
      }),
    )
    renderContent()
    expect(screen.getByTestId('alert-detail-error')).toHaveTextContent('boom')
  })

  it('renders the full detail body for a firing alert', () => {
    vi.spyOn(api, 'useAlertQuery').mockReturnValue(
      makeQuery({ data: makeDetail(), isLoading: false, isError: false }),
    )
    renderContent()
    expect(screen.getByTestId('alert-detail-content')).toBeInTheDocument()
    expect(screen.getByText('Budget burn')).toBeInTheDocument()
    // Agent + fired metadata.
    expect(screen.getByText(/Agent agent-7/)).toBeInTheDocument()
    // No dedup, no silence.
    expect(screen.getByTestId('alert-detail-dedup-status')).toHaveTextContent(
      'No deduplication active',
    )
    expect(screen.getByTestId('alert-detail-suppression-status')).toHaveTextContent(
      'Not silenced',
    )
    // FIRING (non-resolved) → SilenceAction renders.
    expect(screen.getByText('No deliveries recorded.')).toBeInTheDocument()
  })

  it('renders dedup count, silence + routing log + resolved metadata', () => {
    vi.spyOn(api, 'useAlertQuery').mockReturnValue(
      makeQuery({
        data: makeDetail({
          status: 'RESOLVED',
          resolvedAt: '2026-05-14T10:00:00Z',
          dedupOccurrenceCount: 4,
          dedupWindowExpiresAt: '2026-05-14T09:10:00Z',
          silence: {
            silenceId: 'sil-9',
            alertId: 'a-1',
            startsAt: '2026-05-14T09:05:00Z',
            expiresAt: '2026-05-14T09:30:00Z',
            reason: 'maintenance',
            createdBy: 'user-1',
          },
          routingLog: [
            { destinationId: 'dest-1', deliveredAt: '09:01', status: 'ok' },
            {
              destinationId: 'dest-2',
              deliveredAt: '09:02',
              status: 'failed',
              errorMessage: 'timeout',
            },
          ],
        }),
        isLoading: false,
        isError: false,
      }),
    )
    renderContent()
    expect(screen.getByTestId('alert-detail-dedup-status')).toHaveTextContent(
      '4 occurrences within current window',
    )
    expect(screen.getByTestId('alert-detail-suppression-status')).toHaveTextContent(
      'Silenced by sil-9',
    )
    const log = screen.getByTestId('alert-detail-routing-log')
    expect(log).toHaveTextContent('dest-1')
    expect(log).toHaveTextContent('timeout')
    // Resolved → SilenceAction is not rendered.
    expect(screen.getByText(/Resolved/)).toBeInTheDocument()
  })
})
