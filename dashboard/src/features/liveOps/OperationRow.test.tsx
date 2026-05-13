import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { OperationRow } from './OperationRow'
import type { LiveOperation } from './types'

const FIXTURE: LiveOperation = {
  id: 'op-1',
  agent: 'support-agent',
  opType: 'read',
  resource: 'gmail.send',
  status: 'running',
  startedAt: '2026-05-13T14:23:01Z',
  latencyMs: 834,
}

describe('OperationRow', () => {
  it('renders every fixture field', () => {
    render(<OperationRow op={FIXTURE} />)
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
      <OperationRow op={{ ...FIXTURE, id: 'op-tiny', latencyMs: 0.3 }} />,
    )
    expect(screen.getByText('<1ms')).toBeInTheDocument()
    rerender(<OperationRow op={{ ...FIXTURE, id: 'op-slow', latencyMs: 4523 }} />)
    expect(screen.getByText('4.52s')).toBeInTheDocument()
  })

  it('encodes status variants via class + data attribute', () => {
    render(
      <OperationRow op={{ ...FIXTURE, id: 'op-blocked', status: 'blocked' }} />,
    )
    expect(screen.getByText('BLOCKED').className).toContain('op-row__chip--blocked')
  })
})
