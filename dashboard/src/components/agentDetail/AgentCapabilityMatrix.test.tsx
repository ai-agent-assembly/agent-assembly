import { render, screen, fireEvent } from '@testing-library/react'
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

// Mirrors the real projection the ticket describes: `write` populates one
// column, `exec` populates more. `defaultVerb` must therefore land on `exec`,
// not the old hard-coded `write`.
const MATRIX = {
  resources: [
    { id: 'pg', name: 'Postgres', group: 'data', paths: [] },
    { id: 'term', name: 'Terminal', group: 'system', paths: [] },
    { id: 'net', name: 'Network', group: 'system', paths: [] },
  ],
  agents: [
    {
      id: 'abc123', name: 'alpha-agent', framework: 'langgraph', owner: 'alice',
      trust: 72, mode: 'enforce', status: 'active', lastSeen: '2m ago',
      caps: {
        pg: { read: 'na', write: 'deny', delete: 'na', exec: 'na' },
        term: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
        net: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
      },
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
  it('seeds the verb from the loaded matrix rather than hard-coding write', async () => {
    // AAASM-5197 (following AAASM-5125). The tab used to open on `write`, which
    // is populated in one column only; `exec` is the verb this projection
    // actually populates, so `defaultVerb` must land there.
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    expect(await screen.findByTestId('agent-capability-matrix')).toBeInTheDocument()
    expect(screen.getByTestId('agent-capability-matrix-verb-exec')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('agent-capability-matrix-verb-write')).toHaveAttribute('aria-checked', 'false')
  })

  it('switches the active verb when a verb button is clicked', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    fireEvent.click(await screen.findByTestId('agent-capability-matrix-verb-read'))
    expect(screen.getByTestId('agent-capability-matrix-verb-read')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('agent-capability-matrix-verb-exec')).toHaveAttribute('aria-checked', 'false')
  })

  it('opens the drawer render-prop when an interactive cell is clicked', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    const { container } = renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    await screen.findByTestId('agent-capability-matrix')
    // The default verb is `exec`; Network's exec cell is the deny cell on screen.
    const cell = container.querySelector('.cap-mx-cell--deny')
    expect(cell).not.toBeNull()
    fireEvent.click(cell as Element)
    expect(await screen.findByTestId('drawer-open')).toHaveTextContent('Network')
  })

  it('shows the empty state when the agent has no matrix row', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderWith(<AgentCapabilityMatrix agentId="ghost" renderDrawer={drawer} />)
    expect(await screen.findByTestId('agent-capability-matrix-empty')).toBeInTheDocument()
  })

  it('shows the error state when the matrix fetch fails', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockRejectedValue(new Error('boom'))
    renderWith(<AgentCapabilityMatrix agentId="abc123" renderDrawer={drawer} />)
    expect(await screen.findByTestId('agent-capability-matrix-error')).toBeInTheDocument()
  })
})
