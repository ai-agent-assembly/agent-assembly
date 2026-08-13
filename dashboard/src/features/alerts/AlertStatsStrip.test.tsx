import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AlertStatsStrip } from './AlertStatsStrip'
import { coversWholeFleet, statsScopeNote } from './alertsCoverage'
import { absent, known, type Certain } from '../../lib/truthfulness'
import type { Alert, AlertSeverity, AlertStatus } from './types'

function alert(id: string, severity: AlertSeverity, status: AlertStatus): Alert {
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
  alert('a3', 'WARNING', 'FIRING'),
  alert('a4', 'INFO', 'RESOLVED'),
  alert('a5', 'INFO', 'SUPPRESSED'),
]

interface StripProps {
  alerts: Certain<readonly Alert[]>
  total: Certain<number>
  activeSeverities: AlertSeverity[]
  activeStatuses: AlertStatus[]
  onToggleSeverity: (s: AlertSeverity) => void
  onToggleStatus: (s: AlertStatus) => void
}

function renderStrip(overrides: Partial<StripProps> = {}) {
  const props: StripProps = {
    alerts: known(ALERTS),
    total: known(5),
    activeSeverities: [],
    activeStatuses: [],
    onToggleSeverity: vi.fn(),
    onToggleStatus: vi.fn(),
    ...overrides,
  }
  render(<AlertStatsStrip {...props} />)
  return props
}

describe('AlertStatsStrip', () => {
  it('derives the four tile counts from the loaded alerts', () => {
    renderStrip()
    expect(screen.getByTestId('alerts-stat-count-CRITICAL')).toHaveTextContent('2')
    expect(screen.getByTestId('alerts-stat-count-WARNING')).toHaveTextContent('1')
    expect(screen.getByTestId('alerts-stat-count-INFO')).toHaveTextContent('2')
    // Three of the five alerts are FIRING.
    expect(screen.getByTestId('alerts-stat-count-FIRING')).toHaveTextContent('3')
  })

  it('says nothing about scope when the page is the whole fleet', () => {
    renderStrip()
    expect(screen.queryByTestId('alerts-stats-scope')).not.toBeInTheDocument()
  })

  it('states that the counts cover one page when the server reports more', () => {
    renderStrip({ total: known(214) })
    expect(screen.getByTestId('alerts-stats-scope')).toHaveTextContent(
      'Counts cover the 5 alerts on this page, not all 214.',
    )
  })

  it('states the scope caveat when the server did not report a total', () => {
    renderStrip({ total: absent<number>('unknown') })
    expect(screen.getByTestId('alerts-stats-scope')).toHaveTextContent(
      'the server did not report a total',
    )
  })

  it('renders the absence marker rather than 0 when the page failed to load', () => {
    renderStrip({ alerts: absent<readonly Alert[]>('unavailable', 'gateway refused') })
    const critical = screen.getByTestId('alerts-stat-count-CRITICAL')
    expect(critical.textContent).not.toMatch(/\d/)
    expect(critical).toHaveTextContent('—')
    expect(critical.querySelector('[data-truth-state="unavailable"]')).not.toBeNull()
  })

  it('disables the tiles when there is no page to narrow', () => {
    renderStrip({ alerts: absent<readonly Alert[]>('unavailable') })
    expect(screen.getByTestId('alerts-stat-tile-CRITICAL')).toBeDisabled()
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
    expect(screen.getByTestId('alerts-stat-tile-WARNING')).toHaveAttribute('aria-pressed', 'false')
  })
})

describe('coversWholeFleet', () => {
  it('is true only when both numbers are known and the page is not short', () => {
    expect(coversWholeFleet(known(ALERTS), known(5))).toBe(true)
    expect(coversWholeFleet(known(ALERTS), known(6))).toBe(false)
  })

  it('treats an unknown total as not-proven-complete', () => {
    expect(coversWholeFleet(known(ALERTS), absent<number>('unknown'))).toBe(false)
  })

  it('treats an absent page as not-proven-complete', () => {
    expect(coversWholeFleet(absent<readonly Alert[]>('unavailable'), known(0))).toBe(false)
  })
})

describe('statsScopeNote', () => {
  it('has nothing to add when there is no page to describe', () => {
    expect(statsScopeNote(absent<readonly Alert[]>('unavailable'), known(9))).toBeNull()
  })
})
