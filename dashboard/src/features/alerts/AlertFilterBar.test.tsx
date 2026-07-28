import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AlertFilterBar } from './AlertFilterBar'
import { DEFAULT_ALERT_FILTERS, type AlertFilters } from './types'

describe('AlertFilterBar', () => {
  it('toggles severity when the chip is clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<AlertFilterBar value={DEFAULT_ALERT_FILTERS} onChange={onChange} />)
    await user.click(screen.getByTestId('alerts-filter-severity-CRITICAL'))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ severities: ['CRITICAL'] }),
    )
  })

  it('reveals the custom range inputs when range is "custom"', () => {
    const value: AlertFilters = { ...DEFAULT_ALERT_FILTERS, timeRange: 'custom' }
    render(<AlertFilterBar value={value} onChange={vi.fn()} />)
    expect(screen.getByTestId('alerts-filter-custom-from')).toBeInTheDocument()
    expect(screen.getByTestId('alerts-filter-custom-to')).toBeInTheDocument()
  })

  it('removes an already-selected severity when its chip is clicked again', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const value: AlertFilters = { ...DEFAULT_ALERT_FILTERS, severities: ['CRITICAL', 'HIGH'] }
    render(<AlertFilterBar value={value} onChange={onChange} />)
    const chip = screen.getByTestId('alerts-filter-severity-CRITICAL')
    expect(chip).toHaveAttribute('aria-pressed', 'true')
    await user.click(chip)
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ severities: ['HIGH'] }))
  })

  it('toggles a status chip', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<AlertFilterBar value={DEFAULT_ALERT_FILTERS} onChange={onChange} />)
    await user.click(screen.getByTestId('alerts-filter-status-FIRING'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ statuses: ['FIRING'] }))
  })

  it('emits agent query changes', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<AlertFilterBar value={DEFAULT_ALERT_FILTERS} onChange={onChange} />)
    await user.type(screen.getByTestId('alerts-filter-agent'), 'x')
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ agentQuery: 'x' }))
  })

  it('emits free-text search query changes', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<AlertFilterBar value={DEFAULT_ALERT_FILTERS} onChange={onChange} />)
    await user.type(screen.getByTestId('alerts-filter-q'), 'x')
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ q: 'x' }))
  })

  it('emits a new time range when the select changes', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<AlertFilterBar value={DEFAULT_ALERT_FILTERS} onChange={onChange} />)
    await user.selectOptions(screen.getByTestId('alerts-filter-range'), '7d')
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ timeRange: '7d' }))
  })

  it('emits custom from/to bounds and nulls them when cleared', () => {
    const onChange = vi.fn()
    const value: AlertFilters = { ...DEFAULT_ALERT_FILTERS, timeRange: 'custom' }
    render(<AlertFilterBar value={value} onChange={onChange} />)

    fireEvent.change(screen.getByTestId('alerts-filter-custom-from'), {
      target: { value: '2026-05-13T09:00' },
    })
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ customFrom: '2026-05-13T09:00' }),
    )

    fireEvent.change(screen.getByTestId('alerts-filter-custom-to'), { target: { value: '' } })
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ customTo: null }))
  })
})
