import { render, screen } from '@testing-library/react'
import { LoadingState } from './LoadingState'

describe('LoadingState', () => {
  it('renders the generic skeleton by default', () => {
    render(<LoadingState />)
    const region = screen.getByTestId('loading-state-generic')
    expect(region).toBeInTheDocument()
    expect(region).toHaveAttribute('aria-busy')
  })

  it('renders the capability matrix skeleton with one cell per grid slot', () => {
    const { container } = render(<LoadingState page="capability" />)
    expect(screen.getByTestId('loading-state-capability')).toBeInTheDocument()
    expect(container.querySelectorAll('.sk-matrix-cell')).toHaveLength(9 * 7)
  })

  it('renders the fleet table skeleton with one row per placeholder', () => {
    const { container } = render(<LoadingState page="fleet" />)
    expect(screen.getByTestId('loading-state-fleet')).toBeInTheDocument()
    expect(container.querySelectorAll('.sk-table-row')).toHaveLength(8)
  })

  it('renders the overview skeleton variant', () => {
    const { container } = render(<LoadingState page="overview" />)
    expect(screen.getByTestId('loading-state-overview')).toBeInTheDocument()
    // Overview shows a single large block, not matrix/table skeletons.
    expect(container.querySelectorAll('.sk-matrix-cell')).toHaveLength(0)
    expect(container.querySelectorAll('.sk-table-row')).toHaveLength(0)
  })
})
