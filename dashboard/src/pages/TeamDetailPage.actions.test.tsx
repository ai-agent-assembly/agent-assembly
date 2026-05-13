import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { TeamDetailPage } from './TeamDetailPage'
import * as teamsApi from '../features/teams/api'
import * as permissions from '../features/teams/permissions'
import type {
  AgentLineage,
  CostSummary,
  TeamTopology,
  TeamTopologyResult,
} from '../features/teams/api'

function mockQuery<T>(p: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return p as unknown as UseQueryResult<T, Error>
}
function mockMutation<R>(p: { mutate: ReturnType<typeof vi.fn>; isPending: boolean }): R {
  return p as unknown as R
}

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/teams/team-alpha']}>
        <Routes>
          <Route path="/teams/:teamId" element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const TEAM: TeamTopology = {
  team_id: 'team-alpha',
  agent_count: 3,
  members: [
    { id: '11111111111111111111111111111111', name: 'orchestrator', status: 'active', depth: 0, team_id: 'team-alpha' },
    { id: '22222222222222222222222222222222', name: 'worker-1', status: 'active', depth: 1, team_id: 'team-alpha' },
    { id: '33333333333333333333333333333333', name: 'worker-2', status: 'active', depth: 1, team_id: 'team-alpha' },
  ],
}

function mockTeam(result: Partial<TeamTopologyResult> = { data: TEAM }) {
  vi.spyOn(teamsApi, 'useTeamTopologyQuery').mockReturnValue({
    data: undefined, notFound: false, isLoading: false, isError: false, ...result,
  })
}

function mockCosts() {
  vi.spyOn(teamsApi, 'useCostSummaryQuery').mockReturnValue(
    mockQuery<CostSummary>({ data: undefined, isLoading: false, isError: false, refetch: vi.fn() }),
  )
}

function mockLineage() {
  vi.spyOn(teamsApi, 'useAgentLineageQuery').mockReturnValue(
    mockQuery<AgentLineage>({ data: undefined, isLoading: false, isError: false }),
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('TeamDetailPage action bar', () => {
  it('hides Suspend/Resume buttons when the user is not a team admin', async () => {
    vi.spyOn(permissions, 'useCanManageTeam').mockReturnValue(false)
    mockTeam()
    mockCosts()
    mockLineage()
    vi.spyOn(teamsApi, 'useSuspendTeam').mockReturnValue(mockMutation({ mutate: vi.fn(), isPending: false }))
    vi.spyOn(teamsApi, 'useResumeTeam').mockReturnValue(mockMutation({ mutate: vi.fn(), isPending: false }))

    render(<TeamDetailPage />, { wrapper: Wrapper })
    await waitFor(() => expect(screen.getByTestId('team-detail-header')).toBeInTheDocument())
    expect(screen.queryByTestId('team-action-bar')).not.toBeInTheDocument()
  })

  it('shows confirm dialog listing every member before suspending', async () => {
    const user = userEvent.setup()
    vi.spyOn(permissions, 'useCanManageTeam').mockReturnValue(true)
    mockTeam()
    mockCosts()
    mockLineage()
    const suspendMutate = vi.fn()
    vi.spyOn(teamsApi, 'useSuspendTeam').mockReturnValue(
      mockMutation<ReturnType<typeof teamsApi.useSuspendTeam>>({ mutate: suspendMutate, isPending: false }),
    )
    vi.spyOn(teamsApi, 'useResumeTeam').mockReturnValue(
      mockMutation<ReturnType<typeof teamsApi.useResumeTeam>>({ mutate: vi.fn(), isPending: false }),
    )

    render(<TeamDetailPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('team-suspend-btn'))

    const dialog = screen.getByTestId('confirm-dialog')
    expect(dialog).toBeInTheDocument()
    expect(dialog).toHaveTextContent('orchestrator')
    expect(dialog).toHaveTextContent('worker-1')
    expect(dialog).toHaveTextContent('worker-2')
    expect(suspendMutate).not.toHaveBeenCalled()

    await user.click(screen.getByTestId('confirm-ok'))
    expect(suspendMutate).toHaveBeenCalledTimes(1)
    expect(suspendMutate.mock.calls[0][0]).toEqual({
      teamId: 'team-alpha',
      memberIds: TEAM.members.map(m => m.id),
    })
  })

  it('cancel button dismisses the dialog without invoking the mutation', async () => {
    const user = userEvent.setup()
    vi.spyOn(permissions, 'useCanManageTeam').mockReturnValue(true)
    mockTeam()
    mockCosts()
    mockLineage()
    const suspendMutate = vi.fn()
    vi.spyOn(teamsApi, 'useSuspendTeam').mockReturnValue(
      mockMutation<ReturnType<typeof teamsApi.useSuspendTeam>>({ mutate: suspendMutate, isPending: false }),
    )
    vi.spyOn(teamsApi, 'useResumeTeam').mockReturnValue(
      mockMutation<ReturnType<typeof teamsApi.useResumeTeam>>({ mutate: vi.fn(), isPending: false }),
    )

    render(<TeamDetailPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('team-suspend-btn'))
    await user.click(screen.getByTestId('confirm-cancel'))

    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
    expect(suspendMutate).not.toHaveBeenCalled()
  })

  it('surfaces an error toast when the suspend mutation fails', async () => {
    const user = userEvent.setup()
    vi.spyOn(permissions, 'useCanManageTeam').mockReturnValue(true)
    mockTeam()
    mockCosts()
    mockLineage()
    const failingMutate = vi.fn().mockImplementation((_vars, opts) => {
      opts?.onError?.(new Error('boom'))
      opts?.onSettled?.()
    })
    vi.spyOn(teamsApi, 'useSuspendTeam').mockReturnValue(
      mockMutation<ReturnType<typeof teamsApi.useSuspendTeam>>({ mutate: failingMutate, isPending: false }),
    )
    vi.spyOn(teamsApi, 'useResumeTeam').mockReturnValue(
      mockMutation<ReturnType<typeof teamsApi.useResumeTeam>>({ mutate: vi.fn(), isPending: false }),
    )

    render(<TeamDetailPage />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('team-suspend-btn'))
    await user.click(screen.getByTestId('confirm-ok'))

    expect(failingMutate).toHaveBeenCalledTimes(1)
    expect(await screen.findByTestId('team-action-toast')).toHaveTextContent('boom')
  })
})
