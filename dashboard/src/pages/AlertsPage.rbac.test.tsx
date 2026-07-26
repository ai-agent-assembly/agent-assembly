import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AlertsPage } from './AlertsPage'
import { ToastProvider } from '../components/ToastProvider'
import { AuthContext, type AuthContextValue, type Scope } from '../auth/AuthContext'
import * as alertsApi from '../features/alerts/api'
import type { AlertsPageResult } from '../features/alerts/api'
import * as stream from '../features/alerts/useAlertsStream'
import type { AlertRule, Destination } from '../features/alerts/types'

function q<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const RULE: AlertRule = {
  id: 'r-1',
  name: 'Budget burn',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 80,
  evaluationWindowSeconds: 300,
  severity: 'HIGH',
  destinationIds: [],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '',
  updatedAt: '',
}

const DESTINATION: Destination = {
  id: 'd-1',
  kind: 'webhook',
  name: 'Ops webhook',
  enabled: true,
  createdAt: '',
  updatedAt: '',
  config: { url: 'https://hooks.internal/aaasm' },
}

function renderWithScopes(scopes: Scope[], route = '/alerts') {
  vi.spyOn(alertsApi, 'useAlertsPageQuery').mockReturnValue(
    q<AlertsPageResult>({
      data: { items: [], total: 0, page: 1, perPage: 50 },
      isPending: false,
      isLoading: false,
      isError: false,
    }),
  )
  vi.spyOn(alertsApi, 'useAlertRulesQuery').mockReturnValue(
    q<readonly AlertRule[]>({ data: [RULE], isPending: false, isLoading: false, isError: false }),
  )
  vi.spyOn(alertsApi, 'useDestinationsQuery').mockReturnValue(
    q<readonly Destination[]>({
      data: [DESTINATION],
      isPending: false,
      isLoading: false,
      isError: false,
    }),
  )
  vi.spyOn(stream, 'useAlertsStream').mockReturnValue('open')
  const auth: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    logout: () => {},
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <ToastProvider>
          <MemoryRouter initialEntries={[route]}>
            <AlertsPage />
          </MemoryRouter>
        </ToastProvider>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

afterEach(() => vi.restoreAllMocks())

describe('AlertsPage RBAC reflection', () => {
  it('disables the "New rule" control for a read-only caller', () => {
    renderWithScopes(['read'])
    expect(screen.getByTestId('alerts-open-rule-form')).toBeDisabled()
  })

  it('enables the "New rule" control for a write caller', () => {
    renderWithScopes(['write'])
    expect(screen.getByTestId('alerts-open-rule-form')).toBeEnabled()
  })

  // AAASM-5147: every other write surface on the page used to render enabled
  // for a read-scope caller, whose click ended in a raw 403 toast.
  it('disables the rules-tab create / edit / delete controls for a read-only caller', () => {
    renderWithScopes(['read'], '/alerts?tab=rules')
    expect(screen.getByTestId('alert-rules-create')).toBeDisabled()
    expect(screen.getByTestId('alert-rules-row-edit')).toBeDisabled()
    expect(screen.getByTestId('alert-rules-row-delete')).toBeDisabled()
  })

  it('enables the rules-tab controls for a write caller', () => {
    renderWithScopes(['write'], '/alerts?tab=rules')
    expect(screen.getByTestId('alert-rules-row-edit')).toBeEnabled()
    expect(screen.getByTestId('alert-rules-row-delete')).toBeEnabled()
  })

  it('disables every destination mutation for a read-only caller', () => {
    renderWithScopes(['read'])
    fireEvent.click(screen.getByTestId('alerts-open-destinations'))
    expect(screen.getByTestId('destination-form-submit')).toBeDisabled()
    expect(screen.getByTestId('destination-edit-d-1')).toBeDisabled()
    expect(screen.getByTestId('destination-delete-d-1')).toBeDisabled()
    expect(screen.getByTestId('destination-test-d-1')).toBeDisabled()
  })

  it('enables destination mutations for a write caller', () => {
    renderWithScopes(['write'])
    fireEvent.click(screen.getByTestId('alerts-open-destinations'))
    expect(screen.getByTestId('destination-form-submit')).toBeEnabled()
    expect(screen.getByTestId('destination-delete-d-1')).toBeEnabled()
  })

  it('admin satisfies the write requirement', () => {
    renderWithScopes(['admin'], '/alerts?tab=rules')
    expect(screen.getByTestId('alert-rules-row-delete')).toBeEnabled()
  })
})
