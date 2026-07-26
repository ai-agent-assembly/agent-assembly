import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AlertCategoryFilter, type CategoryCounts } from './AlertCategoryFilter'
import { absent, known } from '../../lib/truthfulness'

const COUNTS: CategoryCounts = {
  policy_violation: 3,
  budget: 1,
  anomaly: 0,
  approval: 2,
  uncategorized: 4,
}

describe('AlertCategoryFilter', () => {
  it('renders an all chip plus the four selectable categories with counts', () => {
    render(<AlertCategoryFilter value="all" counts={known(COUNTS)} onChange={vi.fn()} />)
    expect(screen.getByTestId('alerts-category-all')).toBeInTheDocument()
    expect(screen.getByTestId('alerts-category-policy_violation')).toHaveTextContent('3')
    expect(screen.getByTestId('alerts-category-budget')).toHaveTextContent('1')
    // A real zero from a successful join is still a real answer.
    expect(screen.getByTestId('alerts-category-count-anomaly')).toHaveTextContent('0')
    // uncategorized is never a selectable chip.
    expect(screen.queryByTestId('alerts-category-uncategorized')).not.toBeInTheDocument()
  })

  it('emits the selected category on click', () => {
    const onChange = vi.fn()
    render(<AlertCategoryFilter value="all" counts={known(COUNTS)} onChange={onChange} />)
    fireEvent.click(screen.getByTestId('alerts-category-budget'))
    expect(onChange).toHaveBeenCalledWith('budget')
  })

  it('marks the active category pressed', () => {
    render(<AlertCategoryFilter value="anomaly" counts={known(COUNTS)} onChange={vi.fn()} />)
    expect(screen.getByTestId('alerts-category-anomaly')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('alerts-category-all')).toHaveAttribute('aria-pressed', 'false')
  })

  it('renders the absence, not a row of zeroes, when the rules join is unavailable', () => {
    render(
      <AlertCategoryFilter
        value="all"
        counts={absent<CategoryCounts>('unavailable', 'rules request failed')}
        onChange={vi.fn()}
      />,
    )
    for (const cat of ['policy_violation', 'budget', 'anomaly', 'approval']) {
      const chip = screen.getByTestId(`alerts-category-${cat}`)
      expect(chip.textContent).not.toMatch(/\d/)
      expect(chip.querySelector('[data-truth-state="unavailable"]')).not.toBeNull()
    }
  })

  it('disables category selection while the join is unavailable but keeps "all" live', () => {
    render(
      <AlertCategoryFilter
        value="all"
        counts={absent<CategoryCounts>('unavailable')}
        onChange={vi.fn()}
      />,
    )
    expect(screen.getByTestId('alerts-category-budget')).toBeDisabled()
    expect(screen.getByTestId('alerts-category-all')).toBeEnabled()
  })
})
