import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AlertsPage } from './AlertsPage'
import { ToastProvider } from '../components/ToastProvider'
import { AuthContext, type AuthContextValue, type Scope } from '../auth/AuthContext'
import * as alertsApi from '../features/alerts/api'
import * as stream from '../features/alerts/useAlertsStream'
import type { Alert, AlertRule } from '../features/alerts/types'

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

function renderWithScopes(scopes: Scope[]) {
  vi.spyOn(alertsApi, 'useAlertsQuery').mockReturnValue(
    q<readonly Alert[]>({ data: [], isLoading: false, isError: false }),
  )
  vi.spyOn(alertsApi, 'useAlertRulesQuery').mockReturnValue(
    q<readonly AlertRule[]>({ data: [RULE], isLoading: false, isError: false }),
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
          <MemoryRouter initialEntries={['/alerts']}>
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
})
