import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { AgentCapabilityMatrix } from './AgentCapabilityMatrix'
import { capabilityClient } from '../../api/capability'
import type { CapabilityMatrix } from '../../features/capability/types'

function renderWith(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>)
}

const MATRIX = {
  resources: [{ id: 'pg', name: 'Postgres', group: 'data', paths: [] }],
  agents: [
    {
      id: 'abc123', name: 'alpha-agent', framework: 'langgraph', owner: 'alice',
      trust: 72, mode: 'enforce', status: 'active', lastSeen: '2m ago',
      caps: { pg: { read: 'allow', write: 'deny', delete: 'na', exec: 'na' } },
    },
  ],
  policies: [],
  sampleCalls: [],
} as unknown as CapabilityMatrix

function drawer({ cell }: { cell: { resource: { name: string } } | null }) {
  return cell ? <div data-testid="drawer-open">{cell.resource.name}</div> : null
}

afterEach(() => vi.restoreAllMocks())

describe('AgentCapabilityMatrix', () => {
  it('renders the scoped grid with a default verb after loading', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    expect(await screen.findByTestId('agent-capability-matrix')).toBeInTheDocument()
    expect(screen.getByTestId('agent-capability-matrix-verb-write')).toHaveAttribute('aria-checked', 'true')
  })

  it('switches the active verb when a verb button is clicked', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    fireEvent.click(await screen.findByTestId('agent-capability-matrix-verb-read'))
    expect(screen.getByTestId('agent-capability-matrix-verb-read')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('agent-capability-matrix-verb-write')).toHaveAttribute('aria-checked', 'false')
  })

  it('opens the drawer render-prop when an interactive cell is clicked', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    const { container } = renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    await screen.findByTestId('agent-capability-matrix')
    const cell = container.querySelector('.cap-mx-cell--deny')
    expect(cell).not.toBeNull()
    fireEvent.click(cell as Element)
    expect(await screen.findByTestId('drawer-open')).toHaveTextContent('Postgres')
  })

  it('shows the empty state when the agent has no matrix row', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderWith(<AgentCapabilityMatrix agentId="ghost" renderDrawer={drawer} />)
    expect(await screen.findByTestId('agent-capability-matrix-empty')).toBeInTheDocument()
  })

  it('shows the error state when the matrix fetch fails', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockRejectedValue(new Error('boom'))
    renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    await waitFor(() =>
      expect(screen.getByTestId('agent-capability-matrix-error')).toBeInTheDocument(),
    )
  })
})
