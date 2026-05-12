import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FilterBar } from './FilterBar'
import type { FilterParams } from './urlState'

const DEFAULT_FILTERS: FilterParams = { range: '7d', agents: [], teams: [] }

describe('FilterBar', () => {
  it('renders the time range label and select', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByLabelText('Time range')).toBeInTheDocument()
  })

  it('renders all three range options', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByRole('option', { name: 'Last 7 days' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Last 30 days' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Last 90 days' })).toBeInTheDocument()
  })

  it('reflects the current filter range as the selected option', () => {
    render(
      <FilterBar
        filters={{ ...DEFAULT_FILTERS, range: '30d' }}
        onFiltersChange={() => {}}
      />,
    )
    expect(screen.getByRole<HTMLSelectElement>('combobox').value).toBe('30d')
  })

  it('calls onFiltersChange with updated range on select change', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={onChange} />)
    await user.selectOptions(screen.getByRole('combobox'), '90d')
    expect(onChange).toHaveBeenCalledWith({ range: '90d' })
  })

  it('has an accessible search landmark', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByRole('search', { name: 'Analytics filters' })).toBeInTheDocument()
  })
})
