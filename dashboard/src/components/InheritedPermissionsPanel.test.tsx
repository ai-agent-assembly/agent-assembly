import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { InheritedPermissionsPanel } from './InheritedPermissionsPanel'
import * as agentsApi from '../features/agents/api'
import type { EffectivePermissions } from '../features/agents/api'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function renderPanel(agentId = 'aabbccdd00112233aabbccdd00112233') {
  return render(
    <QueryClientProvider client={makeClient()}>
      <InheritedPermissionsPanel agentId={agentId} />
    </QueryClientProvider>,
  )
}

let useAgentCapabilitiesQuery: Mock

beforeEach(() => {
  useAgentCapabilitiesQuery = vi.spyOn(agentsApi, 'useAgentCapabilitiesQuery') as unknown as Mock
})

describe('InheritedPermissionsPanel — loading and error states', () => {
  it('renders loading state while query is pending', () => {
    useAgentCapabilitiesQuery.mockReturnValue(
      mockQuery<EffectivePermissions>({ isLoading: true }),
    )
    renderPanel()
    expect(screen.getByTestId('inherited-permissions-loading')).toBeInTheDocument()
  })

  it('renders error state when query fails', () => {
    useAgentCapabilitiesQuery.mockReturnValue(
      mockQuery<EffectivePermissions>({
        isLoading: false,
        isError: true,
        error: new Error('boom'),
        refetch: vi.fn(),
      }),
    )
    renderPanel()
    expect(screen.getByTestId('inherited-permissions-error')).toBeInTheDocument()
  })
})

describe('InheritedPermissionsPanel — empty cascade', () => {
  it('renders the explicit no-cascade-contribution message when sources is empty', () => {
    useAgentCapabilitiesQuery.mockReturnValue(
      mockQuery<EffectivePermissions>({
        isLoading: false,
        data: { allow: [], deny: [], sources: [] },
      }),
    )
    renderPanel()
    expect(screen.getByTestId('inherited-permissions-empty')).toBeInTheDocument()
    expect(screen.getByText(/No cascade contribution/)).toBeInTheDocument()
  })
})

describe('InheritedPermissionsPanel — populated cascade', () => {
  const data: EffectivePermissions = {
    allow: ['file_read', 'network_outbound', 'mcp_tool:github'],
    deny: ['file_write'],
    sources: [
      {
        scope: 'global',
        allow: ['file_read', 'file_write', 'network_outbound', 'mcp_tool:github'],
        deny: [],
      },
      {
        scope: 'team:platform',
        allow: ['file_read', 'network_outbound', 'mcp_tool:github'],
        deny: ['file_write'],
      },
    ],
  }

  beforeEach(() => {
    useAgentCapabilitiesQuery.mockReturnValue(
      mockQuery<EffectivePermissions>({ isLoading: false, data }),
    )
  })

  it('renders the summary counts', () => {
    renderPanel()
    expect(screen.getByTestId('ipp-allow-count')).toHaveTextContent('3')
    expect(screen.getByTestId('ipp-deny-count')).toHaveTextContent('1')
    expect(screen.getByTestId('ipp-source-count')).toHaveTextContent('2')
  })

  it('groups capabilities by category', () => {
    renderPanel()
    // file_read and file_write → Filesystem group
    expect(screen.getByTestId('ipp-group-filesystem')).toBeInTheDocument()
    // network_outbound → Network
    expect(screen.getByTestId('ipp-group-network')).toBeInTheDocument()
    // mcp_tool:github → MCP
    expect(screen.getByTestId('ipp-group-mcp')).toBeInTheDocument()
  })

  it('shows granted-by chip pointing at the first source that allows each capability', () => {
    renderPanel()
    const fileReadAllow = screen.getByTestId('ipp-allow-file_read')
    expect(fileReadAllow).toHaveTextContent('granted by')
    expect(fileReadAllow).toHaveTextContent('global')
  })

  it('shows denied-by chip pointing at the first source that denies a capability', () => {
    renderPanel()
    const fileWriteDeny = screen.getByTestId('ipp-deny-file_write')
    expect(fileWriteDeny).toHaveTextContent('denied by')
    expect(fileWriteDeny).toHaveTextContent('team:platform')
  })

  it('shows both granted-by and denied-by chips when an ancestor allows but a descendant denies', () => {
    // file_write is allow-listed at the global scope but explicitly denied at
    // team:platform. The panel surfaces both, so operators can see the source
    // of the deny while still understanding that a broader scope intended it
    // to be allowed.
    renderPanel()
    expect(screen.getByTestId('ipp-allow-file_write')).toHaveTextContent('global')
    expect(screen.getByTestId('ipp-deny-file_write')).toHaveTextContent('team:platform')
  })
})
