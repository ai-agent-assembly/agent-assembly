import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { OperationRow } from './OperationRow'
import type { CallStackNode, LiveOperation } from './types'

const CALL_STACK: CallStackNode[] = [
  {
    id: 'llm-1',
    kind: 'llm',
    label: 'gpt-4o · prompt',
    latencyMs: 600,
    children: [
      { id: 'tool-1', kind: 'tool', label: 'query_db', latencyMs: 41 },
      { id: 'result-1', kind: 'result', label: '1 row' },
    ],
  },
]

const FIXTURE: LiveOperation = {
  id: 'op-1',
  agent: 'support-agent',
  opType: known('read'),
  resource: known('gmail.send'),
  status: 'running',
  startedAt: '2026-05-13T14:23:01Z',
  latencyMs: known(834),
  callStack: CALL_STACK,
}

describe('OperationRow', () => {
  it('renders every fixture field', () => {
    render(<OperationRow op={{ ...FIXTURE, callStack: undefined }} />)
    const row = screen.getByTestId('op-row')
    expect(row).toBeInTheDocument()
    expect(row).toHaveAttribute('data-op-id', 'op-1')
    expect(row).toHaveAttribute('data-status', 'running')
    expect(screen.getByText('RUNNING')).toBeInTheDocument()
    expect(screen.getByText('support-agent')).toBeInTheDocument()
    expect(screen.getByTestId('op-row-op-type')).toHaveTextContent('read')
    expect(screen.getByText('834ms')).toBeInTheDocument()
    expect(screen.getByTestId('op-row-resource')).toHaveTextContent('gmail.send')
  })

  it('formats sub-millisecond and second-scale latency', () => {
    const { rerender } = render(
      <OperationRow
        op={{ ...FIXTURE, id: 'op-tiny', latencyMs: known(0.3), callStack: undefined }}
      />,
    )
    expect(screen.getByText('<1ms')).toBeInTheDocument()
    rerender(
      <OperationRow
        op={{ ...FIXTURE, id: 'op-slow', latencyMs: known(4523), callStack: undefined }}
      />,
    )
    expect(screen.getByText('4.52s')).toBeInTheDocument()
  })

  // ── AAASM-5129: no fabricated latency ────────────────────────────────────
  //
  // The regression these lock down: the mapper wrote `latencyMs: 0`
  // unconditionally and `formatLatency` turned anything under 1 into `<1ms`,
  // so every production row claimed a sub-millisecond duration that was never
  // measured. If either half comes back, the first of these fails.

  it('renders the absence, not "<1ms", when no latency was measured', () => {
    render(
      <OperationRow
        op={{
          ...FIXTURE,
          id: 'op-unmeasured',
          latencyMs: absent<number>('unknown', 'not recorded yet'),
          callStack: undefined,
        }}
      />,
    )
    const latency = screen.getByTestId('op-row-latency')
    expect(latency).toHaveAttribute('data-truth-state', 'unknown')
    expect(latency).toHaveTextContent('—')
    // The whole row must be free of a latency claim, not just this cell.
    // Asserted as "no duration string is rendered" rather than "no `ms`
    // substring": the absence carries a screen-reader sentence, and prose
    // legitimately contains those letters.
    expect(screen.queryByText('<1ms')).toBeNull()
    expect(screen.queryByText('0ms')).toBeNull()
    expect(screen.queryByText(/^\d+(\.\d+)?(ms|s)$/)).toBeNull()
  })

  it('renders a measured zero as 0ms, because a measured zero is an answer', () => {
    render(
      <OperationRow
        op={{ ...FIXTURE, id: 'op-zero', latencyMs: known(0), callStack: undefined }}
      />,
    )
    expect(screen.getByTestId('op-row-latency')).toHaveAttribute(
      'data-truth-state',
      'known',
    )
    expect(screen.getByText('0ms')).toBeInTheDocument()
    expect(screen.queryByText('<1ms')).toBeNull()
  })

  it('renders the absence for a verb and resource the event never carried', () => {
    render(
      <OperationRow
        op={{
          ...FIXTURE,
          id: 'op-ops-change',
          opType: absent<string>('not-supported', 'not on ops_change'),
          resource: absent<string>('not-supported', 'not on ops_change'),
          callStack: undefined,
        }}
      />,
    )
    expect(screen.getByTestId('op-row-op-type')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
    const resource = screen.getByTestId('op-row-resource')
    expect(resource).toHaveAttribute('data-truth-state', 'not-supported')
    expect(resource).toHaveTextContent('—')
    // The absent cell no longer renders as a blank chip the operator can read
    // as "no resource involved".
    expect(resource.textContent?.trim()).not.toBe('')
  })

  it('encodes status variants via class + data attribute', () => {
    render(
      <OperationRow
        op={{ ...FIXTURE, id: 'op-blocked', status: 'blocked', callStack: undefined }}
      />,
    )
    expect(screen.getByText('BLOCKED').className).toContain('op-row__chip--blocked')
  })

  it('disables the chevron when no callStack is provided', () => {
    render(<OperationRow op={{ ...FIXTURE, callStack: undefined }} />)
    const chevron = screen.getByTestId('op-row-chevron')
    expect(chevron).toBeDisabled()
    expect(chevron).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByTestId('op-row-tree')).toBeNull()
  })

  it('expands the inline tree when the chevron is clicked', async () => {
    const user = userEvent.setup()
    render(<OperationRow op={FIXTURE} />)
    const chevron = screen.getByTestId('op-row-chevron')
    expect(chevron).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByTestId('op-row-tree')).toBeNull()

    await user.click(chevron)

    expect(chevron).toHaveAttribute('aria-expanded', 'true')
    const tree = screen.getByTestId('op-row-tree')
    expect(tree).toHaveAttribute('role', 'tree')
    expect(screen.getByText('gpt-4o · prompt')).toBeInTheDocument()
    expect(screen.getByText('query_db')).toBeInTheDocument()
    expect(screen.getByText('1 row')).toBeInTheDocument()

    await user.click(chevron)
    expect(chevron).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByTestId('op-row-tree')).toBeNull()
  })

  it('toggles via keyboard (Enter and Space)', async () => {
    const user = userEvent.setup()
    render(<OperationRow op={FIXTURE} />)
    const chevron = screen.getByTestId('op-row-chevron')
    chevron.focus()
    expect(chevron).toHaveFocus()

    await user.keyboard('{Enter}')
    expect(chevron).toHaveAttribute('aria-expanded', 'true')

    await user.keyboard(' ')
    expect(chevron).toHaveAttribute('aria-expanded', 'false')
  })

  it('renders nested tree children with their step kind', () => {
    render(<OperationRow op={FIXTURE} defaultExpanded />)
    expect(screen.getByText('llm').className).toContain('op-row__tree-kind--llm')
    expect(screen.getByText('tool').className).toContain('op-row__tree-kind--tool')
    expect(screen.getByText('result').className).toContain('op-row__tree-kind--result')
  })

  it('hides the row action menu when callbacks are not supplied', () => {
    render(<OperationRow op={{ ...FIXTURE, callStack: undefined }} />)
    expect(screen.queryByTestId('row-action-menu')).toBeNull()
  })

  it('renders the row action menu when all three callbacks are supplied', () => {
    render(
      <OperationRow
        op={{ ...FIXTURE, callStack: undefined }}
        onPause={() => {}}
        onResume={() => {}}
        onTerminate={() => {}}
      />,
    )
    expect(screen.getByTestId('row-action-menu')).toBeInTheDocument()
  })

  it('reflects override prop on data-override and surfaces an inline hint', () => {
    render(
      <OperationRow
        op={{ ...FIXTURE, callStack: undefined }}
        override="pausing"
        onPause={() => {}}
        onResume={() => {}}
        onTerminate={() => {}}
      />,
    )
    const row = screen.getByTestId('op-row')
    expect(row).toHaveAttribute('data-override', 'pausing')
    expect(screen.getByTestId('op-row-override')).toHaveTextContent('pausing…')
  })

  it('starts expanded when defaultExpanded is true', () => {
    render(<OperationRow op={FIXTURE} defaultExpanded />)
    const row = screen.getByTestId('op-row')
    const chevron = screen.getByTestId('op-row-chevron')
    expect(row).toHaveAttribute('data-expanded', 'true')
    expect(chevron).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByTestId('op-row-tree')).toBeInTheDocument()
  })
})
