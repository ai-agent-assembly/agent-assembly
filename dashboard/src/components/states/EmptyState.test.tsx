import { render, screen } from '@testing-library/react'
import { EmptyState } from './EmptyState'

describe('EmptyState', () => {
  it('renders the title as a heading', () => {
    render(<EmptyState title="No policies yet" />)
    expect(screen.getByRole('heading', { name: 'No policies yet' })).toBeInTheDocument()
  })

  it('renders optional description, icon, and action when provided', () => {
    render(
      <EmptyState
        title="No policies yet"
        description="Create your first policy to get started."
        icon={<span data-testid="empty-icon">📄</span>}
        action={<button>New policy</button>}
      />,
    )
    expect(screen.getByText('Create your first policy to get started.')).toBeInTheDocument()
    expect(screen.getByTestId('empty-icon')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'New policy' })).toBeInTheDocument()
  })

  it('omits optional slots when not provided', () => {
    render(<EmptyState title="Title only" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.queryByTestId('empty-icon')).not.toBeInTheDocument()
  })

  it('exposes the surface with the status role for assistive tech', () => {
    render(<EmptyState title="No results" />)
    expect(screen.getByRole('status')).toBe(screen.getByTestId('empty-state'))
  })
})
