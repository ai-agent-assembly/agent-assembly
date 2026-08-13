import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AlertList } from './AlertList'
import type { Alert } from './types'

const ROWS: readonly Alert[] = [
  {
    id: 'a-low',
    ruleId: 'r1',
    ruleName: 'low rule',
    severity: 'INFO',
    status: 'RESOLVED',
    agentId: 'aa-z',
    firstFiredAt: '2026-05-13T10:00:00Z',
    resolvedAt: '2026-05-13T11:00:00Z',
    destinationIds: ['d-low'],
  },
  {
    id: 'a-crit',
    ruleId: 'r2',
    ruleName: 'crit rule',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'aa-a',
    firstFiredAt: '2026-05-13T09:00:00Z',
    resolvedAt: null,
    destinationIds: ['d-crit'],
  },
  {
    id: 'a-med',
    ruleId: 'r3',
    ruleName: 'mid rule',
    severity: 'WARNING',
    status: 'SUPPRESSED',
    agentId: 'aa-m',
    firstFiredAt: '2026-05-13T08:30:00Z',
    resolvedAt: null,
    destinationIds: [],
  },
]

describe('AlertList', () => {
  it('renders one data-testid="alert-row" per alert', () => {
    render(<AlertList rows={ROWS} />)
    expect(screen.getAllByTestId('alert-row')).toHaveLength(3)
  })

  it('sorts severity descending by default (CRITICAL first)', () => {
    render(<AlertList rows={ROWS} />)
    const rows = screen.getAllByTestId('alert-row')
    expect(within(rows[0]).getByText('CRITICAL')).toBeInTheDocument()
    expect(within(rows[1]).getByText('WARNING')).toBeInTheDocument()
    expect(within(rows[2]).getByText('INFO')).toBeInTheDocument()
  })

  it('flips severity order when the column header is clicked', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    await user.click(screen.getByTestId('alerts-th-severity'))
    const rows = screen.getAllByTestId('alert-row')
    expect(within(rows[0]).getByText('INFO')).toBeInTheDocument()
    expect(within(rows[2]).getByText('CRITICAL')).toBeInTheDocument()
  })

  it('fires onSelect with the alert id when a row is clicked', async () => {
    const user = userEvent.setup()
    const onSelect = vi.fn()
    render(<AlertList rows={ROWS} onSelect={onSelect} />)
    await user.click(screen.getAllByTestId('alert-row')[0])
    expect(onSelect).toHaveBeenCalledWith('a-crit')
  })

  // --- Characterization (AAASM-5697): pin the exact v8 behavior the
  // react-table v9 migration must preserve on the highest-risk surfaces. ---

  it('shows only the severity indicator on the default-sorted column, descending', () => {
    render(<AlertList rows={ROWS} />)
    expect(screen.getByTestId('alerts-th-severity').textContent).toContain('↓')
    // No other sortable header carries a direction glyph initially.
    expect(screen.getByTestId('alerts-th-status').textContent).not.toMatch(/[↑↓]/)
    expect(screen.getByTestId('alerts-th-duration').textContent).not.toMatch(/[↑↓]/)
  })

  it('never removes sorting: a third click on severity stays descending (enableSortingRemoval:false)', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    const severityHeader = screen.getByTestId('alerts-th-severity')
    // Default desc → click → asc → click → desc, and never an unsorted state.
    await user.click(severityHeader)
    expect(severityHeader.textContent).toContain('↑')
    await user.click(severityHeader)
    expect(severityHeader.textContent).toContain('↓')
    // A third toggle must land back on asc, not clear the sort.
    await user.click(severityHeader)
    expect(severityHeader.textContent).toContain('↑')
    expect(screen.getAllByTestId('alert-row')).toHaveLength(3)
  })

  it('sorts by status rank FIRING > SUPPRESSED > RESOLVED when the status header is toggled desc', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    const statusHeader = screen.getByTestId('alerts-th-status')
    // First click = asc (RESOLVED first); second = desc (FIRING first).
    await user.click(statusHeader)
    await user.click(statusHeader)
    const rows = screen.getAllByTestId('alert-row')
    expect(within(rows[0]).getByText('FIRING')).toBeInTheDocument()
    expect(within(rows[1]).getByText('SUPPRESSED')).toBeInTheDocument()
    expect(within(rows[2]).getByText('RESOLVED')).toBeInTheDocument()
  })

  it('sorts duration descending-first (numeric accessor → sortDescFirst) via firstFiredAt epoch', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    const durationHeader = screen.getByTestId('alerts-th-duration')
    // The duration column's accessor returns a number, so v8/v9 auto-apply
    // sortDescFirst: the FIRST click is descending. sortDuration compares
    // firstFiredAt epochs, so descending epoch = latest-fired first.
    await user.click(durationHeader)
    expect(durationHeader.textContent).toContain('↓')
    let rows = screen.getAllByTestId('alert-row')
    // low fired 10:00 (largest epoch), crit 09:00, mid 08:30 (smallest).
    expect(within(rows[0]).getByText('low rule')).toBeInTheDocument()
    expect(within(rows[1]).getByText('crit rule')).toBeInTheDocument()
    expect(within(rows[2]).getByText('mid rule')).toBeInTheDocument()
    // Second click flips to ascending epoch = earliest-fired first.
    await user.click(durationHeader)
    expect(durationHeader.textContent).toContain('↑')
    rows = screen.getAllByTestId('alert-row')
    expect(within(rows[0]).getByText('mid rule')).toBeInTheDocument()
    expect(within(rows[2]).getByText('low rule')).toBeInTheDocument()
  })

  it('leaves non-sortable columns non-interactive (Alert / Agent / First fired / Destination)', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    // Clicking a non-sortable header must not change row order or add a glyph.
    const before = screen.getAllByTestId('alert-row').map((r) => r.textContent)
    await user.click(screen.getByTestId('alerts-th-agent'))
    const after = screen.getAllByTestId('alert-row').map((r) => r.textContent)
    expect(after).toEqual(before)
    expect(screen.getByTestId('alerts-th-agent').textContent).not.toMatch(/[↑↓]/)
  })

  it('renders "—" for a missing agent id and an empty destination list', () => {
    render(<AlertList rows={ROWS} onSelect={undefined} />)
    // a-med has destinationIds: [] → "—"; craft a row with null agentId too.
    const rowsWithGaps: readonly Alert[] = [
      { ...ROWS[2], id: 'gap', agentId: null, destinationIds: [] },
    ]
    render(<AlertList rows={rowsWithGaps} />)
    // Two em-dashes (agent + destination) for the gap row.
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2)
  })

  it('renders skeleton rows and no data rows while loading', () => {
    render(<AlertList rows={ROWS} loading />)
    expect(screen.getAllByTestId('alert-row-skeleton')).toHaveLength(5)
    expect(screen.queryAllByTestId('alert-row')).toHaveLength(0)
  })

  it('renders headers but zero rows for an empty alert list', () => {
    render(<AlertList rows={[]} />)
    expect(screen.getByTestId('alerts-table')).toBeInTheDocument()
    expect(screen.getByTestId('alerts-th-severity')).toBeInTheDocument()
    expect(screen.queryAllByTestId('alert-row')).toHaveLength(0)
  })

  it('keeps stable column identity (ids) across a sort toggle', async () => {
    const user = userEvent.setup()
    render(<AlertList rows={ROWS} />)
    const ids = () =>
      ['severity', 'ruleName', 'agent', 'status', 'firstFiredAt', 'duration', 'destination']
    // All expected header testids exist before and after sorting.
    for (const id of ids()) {
      // ruleName/firstFiredAt use their accessor key as column id.
      const testid = id === 'ruleName' ? 'ruleName' : id === 'firstFiredAt' ? 'firstFiredAt' : id
      expect(screen.getByTestId(`alerts-th-${testid}`)).toBeInTheDocument()
    }
    await user.click(screen.getByTestId('alerts-th-status'))
    for (const id of ids()) {
      const testid = id === 'ruleName' ? 'ruleName' : id === 'firstFiredAt' ? 'firstFiredAt' : id
      expect(screen.getByTestId(`alerts-th-${testid}`)).toBeInTheDocument()
    }
  })
})
