/**
 * Write gates on the Fleet bulk-action bar (AAASM-5180).
 *
 * The bar's suspend and resume fan out one mutation per selected agent, so a
 * dropped gate here is a multi-agent write from a read-only caller. Each spec
 * therefore asserts on the *request* — `api.POST` never firing — rather than on
 * the `disabled` attribute alone, which only proves the button looks right.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { FleetPage } from './FleetPage'
import { GrantScopes } from '../auth/GrantScopes'
import { WRITE_REQUIRED_HINT } from '../auth/usePermissions'
import { ToastProvider } from '../components/ToastProvider'
import type { Scope } from '../auth/AuthContext'
import * as agentsApi from '../features/agents/api'
import * as client from '../api/client'
import type { Agent, FleetActiveSession } from '../features/agents/api'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function makeAgent(id: string, name: string): Agent {
  return {
    id,
    name,
    framework: 'langgraph',
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: null,
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    tool_names: [],
    metadata: {},
    pid: null,
  }
}

let post: Mock

beforeEach(() => {
  vi.spyOn(agentsApi, 'useActiveSessionsQuery').mockReturnValue(
    mockQuery<FleetActiveSession[]>({
      data: [],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    }),
  )
  vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
    mockQuery<Agent[]>({
      data: [makeAgent('a', 'alpha'), makeAgent('b', 'beta')],
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    }),
  )
  post = vi.spyOn(client.api, 'POST') as unknown as Mock
  post.mockResolvedValue({
    data: { agent_id: 'a', previous_status: 'active', new_status: 'suspended' },
  })
})

afterEach(() => vi.restoreAllMocks())

/** Render the fleet as `scopes`, with both agents selected so the bar shows. */
async function renderWithSelection(scopes: Scope[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <GrantScopes scopes={scopes}>
        <ToastProvider>
          <MemoryRouter initialEntries={['/agents']}>
            <Routes>
              <Route path="/agents" element={<FleetPage />} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </GrantScopes>
    </QueryClientProvider>,
  )
  fireEvent.click(await screen.findByTestId('fleet-select-all'))
  await screen.findByTestId('fleet-bulkbar')
}

describe('FleetPage bulk-bar write gates', () => {
  it('disables bulk suspend and resume for a read-only caller', async () => {
    await renderWithSelection(['read'])

    const suspend = screen.getByTestId('fleet-bulkbar-suspend')
    const resume = screen.getByTestId('fleet-bulkbar-resume')
    expect(suspend).toBeDisabled()
    expect(suspend).toHaveAttribute('title', WRITE_REQUIRED_HINT)
    expect(resume).toBeDisabled()
    expect(resume).toHaveAttribute('title', WRITE_REQUIRED_HINT)
  })

  it('issues no resume request when a read-only caller clicks resume', async () => {
    await renderWithSelection(['read'])

    // Resume fans out straight to the API with no confirmation step, so the
    // click either reaches the network or it does not — nothing in between.
    fireEvent.click(screen.getByTestId('fleet-bulkbar-resume'))

    await waitFor(() => expect(screen.getByTestId('fleet-bulkbar')).toBeInTheDocument())
    expect(post).not.toHaveBeenCalled()
  })

  it('opens no suspend dialog — and so issues no suspend request — for a read-only caller', async () => {
    await renderWithSelection(['read'])

    fireEvent.click(screen.getByTestId('fleet-bulkbar-suspend'))

    // The reason dialog is the only route to the suspend request; if the gate
    // were dropped it would open here and the fan-out would be one confirm away.
    expect(screen.queryByTestId('suspend-dialog-input')).toBeNull()
    expect(post).not.toHaveBeenCalled()
  })

  it('lets a write caller resume the selection, proving the request path is live', async () => {
    await renderWithSelection(['write'])

    expect(screen.getByTestId('fleet-bulkbar-resume')).toBeEnabled()
    fireEvent.click(screen.getByTestId('fleet-bulkbar-resume'))

    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))
    expect(post).toHaveBeenCalledWith(
      '/api/v1/agents/{id}/resume',
      expect.objectContaining({ params: { path: { id: 'a' } } }),
    )
  })

  it('lets a write caller suspend the selection through the reason dialog', async () => {
    await renderWithSelection(['write'])

    fireEvent.click(screen.getByTestId('fleet-bulkbar-suspend'))
    fireEvent.change(await screen.findByTestId('suspend-dialog-input'), {
      target: { value: 'budget overrun' },
    })
    fireEvent.click(screen.getByTestId('suspend-dialog-confirm'))

    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))
    expect(post).toHaveBeenCalledWith(
      '/api/v1/agents/{id}/suspend',
      expect.objectContaining({ body: { reason: 'budget overrun' } }),
    )
  })

  it('admin satisfies the write requirement', async () => {
    await renderWithSelection(['admin'])
    expect(screen.getByTestId('fleet-bulkbar-suspend')).toBeEnabled()
    expect(screen.getByTestId('fleet-bulkbar-resume')).toBeEnabled()
  })
})
