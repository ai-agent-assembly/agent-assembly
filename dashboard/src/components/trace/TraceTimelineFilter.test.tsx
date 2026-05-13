import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TraceTimelineFilter } from './TraceTimelineFilter'
import { ALL_ON, type SeverityFilter } from './severityFilter'

function setup(initial: SeverityFilter = ALL_ON) {
  const onChange = vi.fn<(next: SeverityFilter) => void>()
  const utils = render(<TraceTimelineFilter value={initial} onChange={onChange} />)
  return { onChange, ...utils }
}

describe('TraceTimelineFilter', () => {
  it('renders four checkboxes labelled Critical / Warning / Info / Neutral, all on by default', () => {
    setup()
    expect(screen.getByTestId('trace-filter-critical')).toBeChecked()
    expect(screen.getByTestId('trace-filter-warning')).toBeChecked()
    expect(screen.getByTestId('trace-filter-info')).toBeChecked()
    expect(screen.getByTestId('trace-filter-neutral')).toBeChecked()
    expect(screen.getByLabelText('Critical')).toBeInTheDocument()
  })

  it('emits a new filter with the toggled key flipped on click', async () => {
    const { onChange } = setup()
    await userEvent.click(screen.getByTestId('trace-filter-warning'))
    expect(onChange).toHaveBeenCalledWith({ ...ALL_ON, warning: false })
  })

  it('reflects controlled value — unchecked keys show as unchecked', () => {
    setup({ critical: true, warning: false, info: true, neutral: false })
    expect(screen.getByTestId('trace-filter-critical')).toBeChecked()
    expect(screen.getByTestId('trace-filter-warning')).not.toBeChecked()
    expect(screen.getByTestId('trace-filter-info')).toBeChecked()
    expect(screen.getByTestId('trace-filter-neutral')).not.toBeChecked()
  })

  it('clears the filter (resets to ALL_ON) when Escape is pressed', async () => {
    const { onChange } = setup({ critical: false, warning: false, info: false, neutral: false })
    await userEvent.click(screen.getByTestId('trace-filter-critical'))
    onChange.mockClear()
    screen.getByTestId('trace-filter').focus()
    await userEvent.keyboard('{Escape}')
    expect(onChange).toHaveBeenCalledWith(ALL_ON)
  })

  it('exposes role=group with an accessible label for screen readers', () => {
    setup()
    expect(screen.getByRole('group', { name: /Filter trace events by severity/i })).toBeInTheDocument()
  })
})
