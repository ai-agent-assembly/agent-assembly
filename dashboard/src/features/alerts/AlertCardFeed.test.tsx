import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AlertCardFeed } from './AlertCardFeed'
import { indexRulesById } from './alertCategory'
import type { Alert, AlertRule } from './types'

const RULE: AlertRule = {
  id: 'r-bud',
  name: 'Budget burn',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 80,
  evaluationWindowSeconds: 300,
  severity: 'CRITICAL',
  destinationIds: [],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '',
  updatedAt: '',
}

const ALERT: Alert = {
  id: 'a-1',
  ruleId: 'r-bud',
  ruleName: 'Budget burn',
  severity: 'CRITICAL',
  status: 'FIRING',
  agentId: 'agent-7',
  firstFiredAt: '2026-05-14T09:00:00Z',
  resolvedAt: null,
  destinationIds: ['dst-slack'],
}

const byId = indexRulesById([RULE])

describe('AlertCardFeed', () => {
  it('renders a severity-bordered card with the derived category chip', () => {
    render(<AlertCardFeed rows={[ALERT]} rulesById={byId} />)
    const card = screen.getByTestId('alert-card')
    expect(card).toHaveStyle({ borderLeftColor: 'var(--severity-critical)' })
    // budget_spent_pct → budget category.
    expect(screen.getByTestId('alert-card-category-budget')).toBeInTheDocument()
    expect(screen.getByText('Budget burn')).toBeInTheDocument()
  })

  it('expands and collapses a card inline on click', () => {
    render(<AlertCardFeed rows={[ALERT]} rulesById={byId} />)
    expect(screen.queryByTestId('alert-card-detail-a-1')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('alert-card-toggle-a-1'))
    expect(screen.getByTestId('alert-card-detail-a-1')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('alert-card-toggle-a-1'))
    expect(screen.queryByTestId('alert-card-detail-a-1')).not.toBeInTheDocument()
  })

  it('opens the detail drawer via the expanded Open detail action', () => {
    const onSelect = vi.fn()
    render(<AlertCardFeed rows={[ALERT]} rulesById={byId} onSelect={onSelect} />)
    fireEvent.click(screen.getByTestId('alert-card-toggle-a-1'))
    fireEvent.click(screen.getByTestId('alert-card-open-detail-a-1'))
    expect(onSelect).toHaveBeenCalledWith('a-1')
  })

  it('renders an empty note when there are no rows', () => {
    render(<AlertCardFeed rows={[]} rulesById={byId} />)
    expect(screen.getByTestId('alert-card-feed-empty')).toBeInTheDocument()
  })
})
