import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AlertCategoryFilter } from './AlertCategoryFilter'
import type { AlertCategory } from './alertCategory'

const COUNTS: Record<AlertCategory, number> = {
  policy_violation: 3,
  budget: 1,
  anomaly: 0,
  approval: 2,
  uncategorized: 4,
}

describe('AlertCategoryFilter', () => {
  it('renders an all chip plus the four selectable categories with counts', () => {
    render(<AlertCategoryFilter value="all" counts={COUNTS} onChange={vi.fn()} />)
    expect(screen.getByTestId('alerts-category-all')).toBeInTheDocument()
    expect(screen.getByTestId('alerts-category-policy_violation')).toHaveTextContent('3')
    expect(screen.getByTestId('alerts-category-budget')).toHaveTextContent('1')
    // uncategorized is never a selectable chip.
    expect(screen.queryByTestId('alerts-category-uncategorized')).not.toBeInTheDocument()
  })

  it('emits the selected category on click', () => {
    const onChange = vi.fn()
    render(<AlertCategoryFilter value="all" counts={COUNTS} onChange={onChange} />)
    fireEvent.click(screen.getByTestId('alerts-category-budget'))
    expect(onChange).toHaveBeenCalledWith('budget')
  })

  it('marks the active category pressed', () => {
    render(<AlertCategoryFilter value="anomaly" counts={COUNTS} onChange={vi.fn()} />)
    expect(screen.getByTestId('alerts-category-anomaly')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('alerts-category-all')).toHaveAttribute('aria-pressed', 'false')
  })
})
