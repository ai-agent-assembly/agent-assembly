import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorState } from './ErrorState'

describe('ErrorState', () => {
  it('renders the title and optional description', () => {
    render(
      <ErrorState
        title="Failed to load policies"
        description="The gateway returned an unexpected error."
      />,
    )
    expect(screen.getByRole('heading', { name: 'Failed to load policies' })).toBeInTheDocument()
    expect(screen.getByText('The gateway returned an unexpected error.')).toBeInTheDocument()
  })

  it('omits the retry button when onRetry is not provided', () => {
    render(<ErrorState title="Something went wrong" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('renders the default "Retry" label when onRetry is provided', () => {
    render(<ErrorState title="Failed" onRetry={() => {}} />)
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('uses a custom retry label when provided', () => {
    render(<ErrorState title="Failed" onRetry={() => {}} retryLabel="Try again" />)
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('invokes onRetry when the retry button is clicked', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    render(<ErrorState title="Failed" onRetry={onRetry} />)
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('marks the surface with role="alert" for assistive tech', () => {
    render(<ErrorState title="Failed" />)
    expect(screen.getByTestId('error-state')).toHaveAttribute('role', 'alert')
  })
})
