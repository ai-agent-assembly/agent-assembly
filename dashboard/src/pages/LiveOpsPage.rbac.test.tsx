/**
 * Page-level write gates for the Live-Ops lane (AAASM-5148).
 *
 * What the feature-level specs cannot reach: the fleet-wide halt-all, whose
 * confirmation dialog lives in a shared component. The dialog's confirm button
 * is the true last control, so the gate has to hold on the dialog itself —
 * including for an operator who opened it while holding `write` and lost the
 * scope before confirming.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../components/ToastProvider'
import { AuthContext, type AuthContextValue, type Scope } from '../auth/AuthContext'
import { WRITE_REQUIRED_HINT } from '../auth/usePermissions'
import { known } from '../lib/truthfulness'
import { useAgentsQuery } from '../features/agents/api'
import { useApprovalsQuery, type Approval } from '../features/approvals/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import * as actions from '../features/liveOps/actions'
import { useLiveOpsStream } from '../features/liveOps/useLiveOpsStream'
import type { LiveOperation } from '../features/liveOps/types'
import { LiveOpsPage } from './LiveOpsPage'

vi.mock('../features/agents/api', () => ({ useAgentsQuery: vi.fn() }))
vi.mock('../features/analytics/useTeamsQuery', () => ({ useTeamsQuery: vi.fn() }))
// Partial mock: `ApprovalActions` renders inside the pane and needs the real
// approve / reject mutation hooks from this module.
vi.mock('../features/approvals/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../features/approvals/api')>()),
  useApprovalsQuery: vi.fn(),
}))
vi.mock('../features/approvals/useApprovalsStream', () => ({
  useApprovalsStream: () => ({ connected: true }),
}))
vi.mock('../features/liveOps/useLiveOpsStream', () => ({ useLiveOpsStream: vi.fn() }))
vi.mock('../features/liveOps/actions', () => ({
  pauseOp: vi.fn(),
  resumeOp: vi.fn(),
  terminateOp: vi.fn(),
  haltAgent: vi.fn(),
  haltGlobal: vi.fn(),
}))
vi.mock('../features/liveOps/PipelineCanvas', () => ({
  PipelineCanvas: () => <div data-testid="pipeline-stub" />,
}))

function makeOp(id: string): LiveOperation {
  return {
    id,
    agent: 'support-agent',
    opType: known('read'),
    resource: known('gmail.send'),
    status: 'running',
    startedAt: '2026-05-13T14:23:01Z',
    latencyMs: known(100),
  }
}

interface ApprovalsOutcome {
  data?: Approval[]
  isPending?: boolean
  isError?: boolean
  error?: unknown
}

function mockApprovals(outcome: ApprovalsOutcome = {}) {
  vi.mocked(useApprovalsQuery).mockReturnValue({
    data: [],
    isPending: false,
    isError: false,
    error: null,
    refetch: vi.fn(),
    ...outcome,
  } as unknown as ReturnType<typeof useApprovalsQuery>)
}

function wrap(scopes: Scope[], ui: ReactElement, client: QueryClient): ReactElement {
  const auth: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    logout: () => {},
  }
  return (
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter>
          <ToastProvider>{ui}</ToastProvider>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>
  )
}

function renderWithScopes(scopes: Scope[]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const view = render(wrap(scopes, <LiveOpsPage />, client))
  return {
    ...view,
    rescope: (next: Scope[]) => view.rerender(wrap(next, <LiveOpsPage />, client)),
  }
}

beforeEach(() => {
  vi.mocked(useAgentsQuery).mockReturnValue({
    data: [],
  } as unknown as ReturnType<typeof useAgentsQuery>)
  vi.mocked(useTeamsQuery).mockReturnValue({
    data: [],
  } as unknown as ReturnType<typeof useTeamsQuery>)
  vi.mocked(useLiveOpsStream).mockReturnValue({
    ops: [makeOp('op-1')],
    status: 'connected',
    reconnect: vi.fn(),
  })
  mockApprovals()
})

afterEach(() => {
  vi.resetAllMocks()
})

describe('LiveOpsPage write gates (AAASM-5148)', () => {
  it('disables the fleet-wide halt-all for a read-only caller', () => {
    renderWithScopes(['read'])
    const halt = screen.getByTestId('live-ops-halt-all')
    expect(halt).toBeDisabled()
    expect(halt).toHaveAttribute('title', WRITE_REQUIRED_HINT)
  })

  it('leaves halt-all live for a write caller', () => {
    renderWithScopes(['write'])
    expect(screen.getByTestId('live-ops-halt-all')).toBeEnabled()
  })

  it('admin satisfies the write requirement for halt-all', () => {
    renderWithScopes(['admin'])
    expect(screen.getByTestId('live-ops-halt-all')).toBeEnabled()
  })

  it('closes an open halt-all dialog when the caller loses write scope', async () => {
    const user = userEvent.setup()
    const { rescope } = renderWithScopes(['write'])

    await user.click(screen.getByTestId('live-ops-halt-all'))
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()

    rescope(['read'])

    expect(screen.queryByTestId('confirm-dialog')).toBeNull()
    expect(actions.haltGlobal).not.toHaveBeenCalled()
  })

  it('leaves the local simulation controls alone — they mutate nothing', () => {
    renderWithScopes(['read'])
    // Speed and pause drive the client-side pipeline animation only. Gating
    // them on write scope would misrepresent them as fleet mutations, which is
    // the conflation the pause/stream audit (AAASM-5153) is about.
    expect(screen.getByTestId('live-ops-faster')).toBeEnabled()
    expect(screen.getByTestId('live-ops-pause')).toBeEnabled()
  })
})
