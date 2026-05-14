import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
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
  opType: 'read',
  resource: 'gmail.send',
  status: 'running',
  startedAt: '2026-05-13T14:23:01Z',
  latencyMs: 834,
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
    expect(screen.getByText('read')).toBeInTheDocument()
    expect(screen.getByText('834ms')).toBeInTheDocument()
    expect(screen.getByText('gmail.send')).toBeInTheDocument()
  })

  it('formats sub-millisecond and second-scale latency', () => {
    const { rerender } = render(
      <OperationRow
        op={{ ...FIXTURE, id: 'op-tiny', latencyMs: 0.3, callStack: undefined }}
      />,
    )
    expect(screen.getByText('<1ms')).toBeInTheDocument()
    rerender(
      <OperationRow
        op={{ ...FIXTURE, id: 'op-slow', latencyMs: 4523, callStack: undefined }}
      />,
    )
    expect(screen.getByText('4.52s')).toBeInTheDocument()
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
