import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Outlet, Routes, Route, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityPage } from './CapabilityPage'
import { ToastProvider } from '../components/ToastProvider'
import { capabilityClient } from '../api/capability'
import { CAPABILITY_MATRIX_FIXTURE } from '../features/capability/fixtures'
import { defaultVerb } from '../features/capability/verb'
import type { CapabilityMatrix } from '../features/capability/types'

vi.mock('../api/capability', () => ({
  capabilityClient: {
    getMatrix: vi.fn(),
    applyOverride: vi.fn(),
  },
}))

const getMatrix = capabilityClient.getMatrix as ReturnType<typeof vi.fn>
const applyOverride = capabilityClient.applyOverride as ReturnType<typeof vi.fn>

function LocationProbe() {
  const loc = useLocation()
  return <div data-testid="location">{`${loc.pathname}${loc.search}`}</div>
}

function renderPage() {
  // A throwaway client per render, with retries off so a rejected fetch surfaces
  // the error state immediately instead of being retried.
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
    <ToastProvider>
      <MemoryRouter initialEntries={['/capability']}>
        <Routes>
          <Route path="/capability" element={<CapabilityPage />} />
          <Route path="/policies" element={<div>policy editor route</div>} />
          {/* Mirrors App.tsx: the agent drawer is a child route of Fleet, so a
              link that only matched a flat `/agents/:id` would still 404 in the
              app. Nesting it here means the run proves the URL the page emits
              resolves against the shape the router actually declares. */}
          <Route path="/agents" element={<Outlet />}>
            <Route path=":id" element={<div>agent detail route</div>} />
          </Route>
        </Routes>
        <LocationProbe />
      </MemoryRouter>
    </ToastProvider>
    </QueryClientProvider>,
  )
}

const FIXTURE = CAPABILITY_MATRIX_FIXTURE

/**
 * The matrix shaped the way the live endpoint actually shapes it.
 *
 * `GET /capability/matrix` projects a static capability set, so every cell it
 * emits is `allow`, `deny` or `na` — `narrow` and `approval` are decided by
 * policy stages the projection does not run. The design fixture still carries
 * all five for the legend's sake, which would mask a `narrow` cell painted by
 * the override path, so the optimistic-render run below folds it down first.
 */
const PROJECTION_MATRIX: CapabilityMatrix = {
  ...FIXTURE,
  agents: FIXTURE.agents.map((agent) => ({
    ...agent,
    caps: Object.fromEntries(
      Object.entries(agent.caps).map(([resourceId, cell]) => [
        resourceId,
        Object.fromEntries(
          Object.entries(cell).map(([key, value]) =>
            value === 'narrow' || value === 'approval' ? [key, 'allow'] : [key, value],
          ),
        ),
      ]),
    ) as typeof agent.caps,
  })),
}

/**
 * The matrix shaped the way `project_matrix` shapes a real fleet: read/write/
 * delete on the Filesystem family only, `exec` on Terminal, Network-outbound
 * and every MCP-tool column (`aa-api/src/routes/capability.rs:497-524`).
 */
const EXEC_HEAVY_MATRIX: CapabilityMatrix = {
  resources: [
    { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
    { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
    { id: 'network-outbound', name: 'Network', group: 'infra', paths: [] },
  ],
  agents: [
    {
      id: 'a1',
      name: 'research-bot',
      framework: 'langgraph',
      trust: null,
      status: 'active',
      lastSeen: '2026-07-26T00:00:00Z',
      caps: {
        filesystem: { read: 'allow', write: 'allow', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
        'network-outbound': { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
      },
    },
  ],
  policies: FIXTURE.policies,
  sampleCalls: [],
}

/**
 * The first resource column of the grid — the column the run overrides.
 *
 * The matrix is one flat CSS grid, so its cells come back in row-major order
 * with `resources.length` of them per agent row.
 */
function firstColumn(): HTMLElement[] {
  const width = PROJECTION_MATRIX.resources.length
  return screen.getAllByRole('gridcell').filter((_, i) => i % width === 0)
}

/**
 * Drive the bulk bar the way an operator now has to (AAASM-5124).
 *
 * There is no pre-selected decision and no one-click write: a decision must be
 * chosen, then the write confirmed. Every run below that expects a POST goes
 * through here, so if either gate is removed they all fail rather than silently
 * exercising a shortcut.
 */
function recordOverride(decision: string, resourceId?: string) {
  fireEvent.change(screen.getByLabelText('decision'), { target: { value: decision } })
  if (resourceId) {
    fireEvent.change(screen.getByLabelText('resource'), { target: { value: resourceId } })
  }
  fireEvent.click(screen.getByRole('button', { name: 'Record display-only override' }))
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
}

beforeEach(() => {
  getMatrix.mockReset()
  applyOverride.mockReset()
})

afterEach(() => vi.restoreAllMocks())

describe('CapabilityPage', () => {
  it('shows the loading state before the matrix resolves', async () => {
    let resolve!: (m: CapabilityMatrix) => void
    getMatrix.mockReturnValue(new Promise<CapabilityMatrix>((r) => (resolve = r)))
    renderPage()
    expect(screen.getByTestId('loading-state-capability')).toBeInTheDocument()
    resolve(FIXTURE)
    await screen.findByRole('heading', { name: /Capability/ })
  })

  it('renders the error state and retries on click', async () => {
    getMatrix.mockRejectedValueOnce(new Error('boom'))
    renderPage()
    const retry = await screen.findByRole('button', { name: /retry/i })
    // On retry, return a real matrix.
    getMatrix.mockResolvedValueOnce(FIXTURE)
    fireEvent.click(retry)
    await screen.findByRole('heading', { name: /Capability/ })
    expect(getMatrix).toHaveBeenCalledTimes(2)
  })

  it('renders the empty state when the matrix has no agents', async () => {
    getMatrix.mockResolvedValueOnce({ ...FIXTURE, agents: [] })
    renderPage()
    expect(await screen.findByTestId('empty-state-capability')).toBeInTheDocument()
  })

  it('renders the matrix view with the header and switches tabs / verb', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    // Matrix tab active by default → filter bar present.
    expect(screen.getByRole('search')).toBeInTheDocument()

    // Switch to the Per-agent tab.
    fireEvent.click(screen.getByRole('button', { name: 'Per-agent' }))
    expect(screen.queryByRole('search')).not.toBeInTheDocument()

    // Switch the verb radio.
    const readRadio = screen.getByRole('radio', { name: 'read' })
    fireEvent.click(readRadio)
    expect(readRadio).toHaveAttribute('aria-checked', 'true')
  })

  it('shows the matrix tab count badge and the summary row', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    // Tab badge: <visible> × <resources>.
    expect(
      screen.getByText(`${FIXTURE.agents.length} × ${FIXTURE.resources.length}`),
    ).toBeInTheDocument()
    // Summary row. Three tiles, not four: the `narrowed` tile was removed with
    // AAASM-5187 because the projection cannot emit a narrowed cell, so its
    // count could only ever be a fabricated zero (ADR 0026 Decision 2).
    const summary = screen.getByLabelText('matrix summary')
    expect(summary).toBeInTheDocument()
    expect(summary).not.toHaveTextContent('narrowed')
    expect(summary).toHaveTextContent('denied')
    expect(summary).toHaveTextContent('flagged agents')
    // The verb in the label is the one the page landed on, derived from the
    // fixture rather than hard-coded (AAASM-5125).
    expect(summary).toHaveTextContent(
      `total "allow" cells (${defaultVerb(FIXTURE.agents, FIXTURE.resources)})`,
    )
  })

  /**
   * AAASM-5125. The page opened on `write`, which the live projection models on
   * the Filesystem column alone — every other column is `exec`-only — so the
   * flagship governance page landed on one populated column and a wall of n/a.
   */
  it('lands on the verb the loaded matrix populates, not on write', async () => {
    getMatrix.mockResolvedValue(EXEC_HEAVY_MATRIX)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    expect(screen.getByRole('radio', { name: 'exec' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('radio', { name: 'write' })).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByLabelText('matrix summary')).toHaveTextContent(
      'total "allow" cells (exec)',
    )
  })

  it("keeps the operator's chosen verb even though the default is derived", async () => {
    // The derivation is a landing default, not a constraint: an explicit choice
    // must survive, including a choice of the verb the data does not favour.
    getMatrix.mockResolvedValue(EXEC_HEAVY_MATRIX)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    fireEvent.click(screen.getByRole('radio', { name: 'write' }))
    expect(screen.getByRole('radio', { name: 'write' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByLabelText('matrix summary')).toHaveTextContent(
      'total "allow" cells (write)',
    )
  })

  /**
   * AAASM-5154 — the matrix is where an over-permissioned agent is spotted, and
   * the row header had no way to reach that agent. The destination is asserted
   * to *resolve*, not merely to be pushed: the Trace surface shipped a row link
   * to a route that 404'd (AAASM-5109), which a URL-only assertion would miss.
   */
  it('opens the agent detail route from a matrix row header', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    const first = FIXTURE.agents[0]
    fireEvent.click(screen.getByRole('button', { name: `open agent ${first.name}` }))
    expect(await screen.findByText('agent detail route')).toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent(`/agents/${first.id}`)
  })

  it('navigates to the policy editor from the Open Policy editor button', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    fireEvent.click(screen.getByRole('button', { name: /Open Policy editor/ }))
    expect(await screen.findByText('policy editor route')).toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent('/policies')
  })

  it('navigates to a policy from a drawer edit link', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    // Find a cell that has responsible policies (narrow/deny/approval), open it.
    const cell = screen
      .getAllByRole('gridcell')
      .find((c) => c.dataset.decision === 'narrow' || c.dataset.decision === 'deny')
    expect(cell).toBeDefined()
    fireEvent.click(cell!)
    await screen.findByRole('dialog', { name: 'capability cell inspect' })
    const editLink = screen.queryByRole('button', { name: 'edit →' })
    if (editLink) {
      fireEvent.click(editLink)
      expect(screen.getByTestId('location')).toHaveTextContent('/policies?policy=')
    }
  })

  it('opens the cell inspect drawer when a matrix cell is clicked', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    const interactiveCell = screen
      .getAllByRole('gridcell')
      .find((c) => c.dataset.decision !== 'na')
    expect(interactiveCell).toBeDefined()
    fireEvent.click(interactiveCell!)
    expect(
      await screen.findByRole('dialog', { name: 'capability cell inspect' }),
    ).toBeInTheDocument()
  })

  it('records a bulk override and toasts what actually changed', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    applyOverride.mockResolvedValueOnce({ updated: [] })
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })

    // Select all agents via the matrix select-all checkbox.
    fireEvent.click(screen.getByLabelText('select all agents'))
    recordOverride('deny', FIXTURE.resources[0].id)

    await waitFor(() => expect(applyOverride).toHaveBeenCalledTimes(1))

    // AAASM-5178: the override store has never fed enforcement, so the success
    // report may not read as though a gateway decision moved. It says the
    // annotation landed, and says enforcement did not follow it.
    const toast = await screen.findByText(/display-only override recorded/)
    expect(toast).toHaveTextContent('gateway enforcement did not')
    expect(screen.queryByText(/^override applied to/)).not.toBeInTheDocument()
  })

  it('does not write when the operator never confirms', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    fireEvent.click(screen.getByLabelText('select all agents'))

    // Choosing a decision and pressing the primary control is not yet a write.
    fireEvent.change(screen.getByLabelText('decision'), { target: { value: 'deny' } })
    fireEvent.click(screen.getByRole('button', { name: 'Record display-only override' }))
    expect(applyOverride).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(applyOverride).not.toHaveBeenCalled())
  })

  it('cannot write at all before a decision is chosen', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    fireEvent.click(screen.getByLabelText('select all agents'))

    // The bar is on screen with a live selection, and the write is unreachable —
    // there is no decision that an unconsidered click could submit.
    expect(screen.getByRole('region', { name: 'bulk override' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Record display-only override' }))
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument()
    await waitFor(() => expect(applyOverride).not.toHaveBeenCalled())
  })

  it('re-syncs with the server projection after a successful override', async () => {
    // The server replays the override onto its own projection, so the refetch is
    // authoritative. Before the fix the optimistic copy shadowed `data` forever:
    // this refetch resolved and was silently discarded, freezing the page.
    const refetched: CapabilityMatrix = {
      ...FIXTURE,
      agents: FIXTURE.agents.map((a, i) => (i === 0 ? { ...a, name: 'renamed-by-server' } : a)),
    }
    getMatrix.mockResolvedValueOnce(FIXTURE).mockResolvedValue(refetched)
    applyOverride.mockResolvedValueOnce({ updated: [] })
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })

    fireEvent.click(screen.getByLabelText('select all agents'))
    recordOverride('deny', FIXTURE.resources[0].id)

    expect(await screen.findByText('renamed-by-server')).toBeInTheDocument()
  })

  it('rolls back and toasts on a failed bulk override', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    applyOverride.mockRejectedValueOnce(new Error('gateway said no'))
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    fireEvent.click(screen.getByLabelText('select all agents'))
    recordOverride('deny')
    expect(await screen.findByText(/rollback: gateway said no/)).toBeInTheDocument()
  })

  it('never paints a decision the projection cannot produce, in flight or after', async () => {
    // The page applies the override optimistically — `setOptimistic(...)` runs
    // *before* the POST is answered — so whatever the bulk bar can submit is on
    // screen for the length of the round-trip. When the bar defaulted to
    // `narrow` that meant the grid rendered `narrow` cells the gateway was about
    // to 400, then rolled them back (AAASM-5124).
    getMatrix.mockResolvedValue(PROJECTION_MATRIX)
    let settle!: () => void
    applyOverride.mockReturnValue(new Promise<void>((r) => (settle = () => r())))
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })

    const impossibleCells = () =>
      screen
        .getAllByRole('gridcell')
        .filter((c) => c.dataset.decision === 'narrow' || c.dataset.decision === 'approval')

    expect(impossibleCells()).toHaveLength(0)
    // Something in the column has to change, or "every cell reads deny" below
    // would hold without the optimistic edit ever running.
    expect(firstColumn().some((c) => c.dataset.decision !== 'deny')).toBe(true)

    fireEvent.click(screen.getByLabelText('select all agents'))
    recordOverride('deny', PROJECTION_MATRIX.resources[0].id)

    // In flight: the optimistic edit is on screen — so this run really does
    // exercise the pre-POST paint — and it is a decision the projection emits.
    await waitFor(() => expect(applyOverride).toHaveBeenCalledTimes(1))
    expect(impossibleCells()).toHaveLength(0)
    expect(firstColumn().every((c) => c.dataset.decision === 'deny')).toBe(true)

    settle()
    await waitFor(() => expect(getMatrix).toHaveBeenCalledTimes(2))
    expect(impossibleCells()).toHaveLength(0)
  })

  it('clears the selection via the bulk Clear button', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    fireEvent.click(screen.getByLabelText('select all agents'))
    // BulkActionBar is visible while there is a selection.
    expect(screen.getByRole('region', { name: 'bulk override' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(
      screen.queryByRole('region', { name: 'bulk override' }),
    ).not.toBeInTheDocument()
  })

  it('sorts the matrix when a column header is clicked', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    const header = screen.getAllByRole('columnheader')[1]
    fireEvent.click(header)
    // First click sets a descending sort on that resource column.
    expect(header).toHaveAttribute('aria-sort', 'descending')
  })

  it('closes the cell inspect drawer', async () => {
    getMatrix.mockResolvedValue(FIXTURE)
    renderPage()
    await screen.findByRole('heading', { name: /Capability/ })
    const cell = screen
      .getAllByRole('gridcell')
      .find((c) => c.dataset.decision !== 'na')!
    fireEvent.click(cell)
    await screen.findByRole('dialog', { name: 'capability cell inspect' })
    fireEvent.click(screen.getByLabelText('close drawer'))
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'capability cell inspect' }),
      ).not.toBeInTheDocument(),
    )
  })
})
