import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AlertStatsStrip } from './AlertStatsStrip'
import type { Alert, Severity, AlertStatus } from './types'

function alert(id: string, severity: Severity, status: AlertStatus): Alert {
  return {
    id,
    ruleId: 'r',
    ruleName: 'r',
    severity,
    status,
    agentId: null,
    firstFiredAt: '2026-05-14T09:00:00Z',
    resolvedAt: null,
    destinationIds: [],
  }
}

const ALERTS: readonly Alert[] = [
  alert('a1', 'CRITICAL', 'FIRING'),
  alert('a2', 'CRITICAL', 'FIRING'),
  alert('a3', 'HIGH', 'FIRING'),
  alert('a4', 'MEDIUM', 'RESOLVED'),
  alert('a5', 'LOW', 'SUPPRESSED'),
]

function renderStrip(overrides = {}) {
  const props = {
    alerts: ALERTS,
    activeSeverities: [] as Severity[],
    activeStatuses: [] as AlertStatus[],
    onToggleSeverity: vi.fn(),
    onToggleStatus: vi.fn(),
    ...overrides,
  }
  render(<AlertStatsStrip {...props} />)
  return props
}

describe('AlertStatsStrip', () => {
  it('derives the five tile counts from the loaded alerts', () => {
    renderStrip()
    expect(screen.getByTestId('alerts-stat-count-CRITICAL')).toHaveTextContent('2')
    expect(screen.getByTestId('alerts-stat-count-HIGH')).toHaveTextContent('1')
    expect(screen.getByTestId('alerts-stat-count-MEDIUM')).toHaveTextContent('1')
    expect(screen.getByTestId('alerts-stat-count-LOW')).toHaveTextContent('1')
    // Three of the five alerts are FIRING.
    expect(screen.getByTestId('alerts-stat-count-FIRING')).toHaveTextContent('3')
  })

  it('toggles the matching severity filter when a severity tile is clicked', () => {
    const props = renderStrip()
    fireEvent.click(screen.getByTestId('alerts-stat-tile-CRITICAL'))
    expect(props.onToggleSeverity).toHaveBeenCalledWith('CRITICAL')
    expect(props.onToggleStatus).not.toHaveBeenCalled()
  })

  it('toggles the FIRING status filter when the firing tile is clicked', () => {
    const props = renderStrip()
    fireEvent.click(screen.getByTestId('alerts-stat-tile-FIRING'))
    expect(props.onToggleStatus).toHaveBeenCalledWith('FIRING')
  })

  it('marks a tile pressed when its filter is active', () => {
    renderStrip({ activeSeverities: ['CRITICAL'] })
    expect(screen.getByTestId('alerts-stat-tile-CRITICAL')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('alerts-stat-tile-HIGH')).toHaveAttribute('aria-pressed', 'false')
  })
})
