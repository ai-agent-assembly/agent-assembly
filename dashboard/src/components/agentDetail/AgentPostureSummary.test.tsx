import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AgentPostureSummary } from './AgentPostureSummary'
import { capabilityClient } from '../../api/capability'
import type { CapabilityMatrix } from '../../features/capability/types'

const MATRIX = {
  resources: [
    { id: 'gmail', name: 'Gmail', group: 'comm', paths: [] },
    { id: 'pg', name: 'Postgres', group: 'data', paths: [] },
  ],
  policies: [
    { id: 'P-001', name: 'global default-deny', scope: 'global', status: 'active', affects: [], rules: [] },
  ],
  sampleCalls: [],
  agents: [
    {
      id: 'abc123',
      name: 'alpha-agent',
      framework: 'langgraph',
      owner: 'alice',
      trust: null,
      mode: 'enforce',
      status: 'active',
      lastSeen: '2m ago',
      caps: {
        gmail: { read: 'allow', write: 'deny', delete: 'na', exec: 'na' },
        pg: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
      },
    },
  ],
} as unknown as CapabilityMatrix

// `null` rather than `undefined` for "no name": passing `undefined` explicitly
// still triggers the default parameter, which would silently keep the name
// fallback alive in the test that exists to switch it off.
function renderPanel(agentId = 'abc123', agentName: string | null = 'alpha-agent') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <AgentPostureSummary agentId={agentId} agentName={agentName ?? undefined} />
    </QueryClientProvider>,
  )
}

/**
 * Wait for a figure to settle on an expected state.
 *
 * The rows are on screen from the first frame — carrying `unknown` while the
 * request is in flight — so a bare `findByTestId` resolves against the pending
 * panel and asserts nothing about the settled one.
 */
async function settled(testId: string, state: string) {
  await vi.waitFor(() =>
    expect(screen.getByTestId(testId)).toHaveAttribute('data-truth-state', state),
  )
}

/** The visible figure with the screen-reader sentence stripped. */
function figure(testId: string): string {
  const el = screen.getByTestId(testId).cloneNode(true) as HTMLElement
  el.querySelectorAll('.truth-sr-only').forEach((n) => n.remove())
  return el.textContent?.trim() ?? ''
}

afterEach(() => vi.restoreAllMocks())

describe('AgentPostureSummary — a loaded matrix', () => {
  it('renders allow and deny as counts drawn from the capability cells', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderPanel()
    await settled('agent-posture-allow', 'known')
    expect(figure('agent-posture-allow')).toBe('2')
    expect(figure('agent-posture-deny')).toBe('3')
  })

  it('never renders a zero for narrow or approval', async () => {
    // AAASM-5131 regression guard. The panel hardcoded `value={0}` for both
    // rows, which read as "nothing narrowed, no approvals needed" on the
    // surface an operator opens to investigate a single agent.
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderPanel()
    await settled('agent-posture-allow', 'known')
    for (const row of ['agent-posture-narrow', 'agent-posture-approval']) {
      expect(screen.getByTestId(row)).toHaveAttribute('data-truth-state', 'not-supported')
      expect(figure(row)).toBe('—')
      expect(figure(row)).not.toContain('0')
    }
  })

  it('draws a fill only for the rows it measured', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    const { container } = renderPanel()
    await settled('agent-posture-allow', 'known')
    // A zero-width bar is what a measured zero looks like; an unmeasured row
    // must have no bar at all.
    expect(container.querySelectorAll('.ad-minibar__fill')).toHaveLength(2)
    expect(
      screen.getByTestId('agent-posture-narrow-row').querySelector('.ad-minibar__fill'),
    ).toBeNull()
  })

  it('announces each absence rather than leaving a bare dash', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderPanel()
    await settled('agent-posture-narrow', 'not-supported')
    expect(screen.getByTestId('agent-posture-narrow').querySelector('.truth-sr-only')?.textContent).toContain(
      'the backend cannot provide this value',
    )
  })

  it('states on the surface why two rows can never carry a number', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    renderPanel()
    expect(await screen.findByTestId('agent-posture-caption')).toHaveTextContent(
      /decided per action by other policy stages/i,
    )
  })
})

describe('AgentPostureSummary — the matrix is not trustworthy', () => {
  it('renders unavailable, not a posture, when the request fails', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockRejectedValue(new Error('boom'))
    renderPanel()
    await settled('agent-posture-allow', 'unavailable')
    expect(screen.getByTestId('agent-posture-deny')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
    for (const row of ['allow', 'deny', 'narrow', 'approval']) {
      expect(figure(`agent-posture-${row}`)).toBe('—')
    }
    expect(screen.getByTestId('agent-detail-posture').textContent).toContain(
      'the request for this value failed',
    )
  })

  it('reports not-evaluated when the agent has no row in the matrix', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue(MATRIX)
    // No `agentName`, so the hook's name fallback cannot resolve a row either.
    renderPanel('ghost', null)
    await settled('agent-posture-allow', 'not-evaluated')
    expect(figure('agent-posture-deny')).toBe('—')
  })

  it('reports unconfigured when no policy document backs the verdicts', async () => {
    vi.spyOn(capabilityClient, 'getMatrix').mockResolvedValue({ ...MATRIX, policies: [] })
    renderPanel()
    await settled('agent-posture-allow', 'unconfigured')
    expect(figure('agent-posture-allow')).toBe('—')
  })
})
