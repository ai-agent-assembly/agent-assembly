import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { StatusChip } from './StatusChip'

describe('StatusChip', () => {
  it('styles each known status with its own kind', () => {
    for (const status of ['active', 'idle', 'suspended', 'error'] as const) {
      const { unmount } = render(<StatusChip status={status} />)
      expect(screen.getByTestId('fleet-status')).toHaveClass(`fleet-status--${status}`)
      unmount()
    }
  })

  it('tones a running session as active while keeping the running label', () => {
    // The active-sessions endpoint emits "running"; it must read as active
    // (green), not fall into the grey unknown bucket, and the label must stay
    // truthful to what the wire said (AAASM-5172).
    render(<StatusChip status="running" />)
    const chip = screen.getByTestId('fleet-status')
    expect(chip).toHaveClass('fleet-status--active')
    expect(chip).toHaveTextContent('running')
  })

  it('falls back to the unknown kind for an unrecognised status', () => {
    render(<StatusChip status="quarantined" />)
    expect(screen.getByTestId('fleet-status')).toHaveClass('fleet-status--unknown')
  })
})
