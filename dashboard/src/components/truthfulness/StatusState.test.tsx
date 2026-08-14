import { render, screen } from '@testing-library/react'
import { TRUTH_STATES, TRUTH_STATE_META } from '../../lib/truthfulness'
import { StatusState } from './StatusState'

describe('StatusState', () => {
  it.each(TRUTH_STATES)('renders the %s state with its badge and announcement', (state) => {
    render(<StatusState state={state} title="No verdict" />)
    const surface = screen.getByTestId('status-state')
    expect(surface).toHaveAttribute('data-truth-state', state)
    expect(surface.className).toContain(`truth-state--${state}`)
    expect(surface).toHaveTextContent(TRUTH_STATE_META[state].label)
    expect(surface).toHaveTextContent(TRUTH_STATE_META[state].announcement)
  })

  it('announces a failed request assertively and everything else politely', () => {
    // role="alert" interrupts the user, so it is reserved for the one state
    // that means something is broken. The rest are still announced.
    render(<StatusState state="unavailable" title="Failed" />)
    expect(screen.getByTestId('status-state')).toHaveAttribute('role', 'alert')

    for (const state of TRUTH_STATES.filter((s) => s !== 'unavailable')) {
      const { unmount } = render(<StatusState state={state} title="No verdict" testId={state} />)
      expect(screen.getByTestId(state)).toHaveAttribute('role', 'status')
      unmount()
    }
  })

  it('treats a genuinely empty result as a known answer, not an absence', () => {
    // "The query succeeded and returned zero rows" is a fact, so it carries no
    // absence badge and no fault tone.
    render(<StatusState state={null} title="No policies yet" />)
    const surface = screen.getByTestId('status-state')
    expect(surface).toHaveAttribute('data-truth-state', 'empty')
    expect(surface).toHaveAttribute('role', 'status')
    expect(surface.querySelector('.truth-state__badge')).toBeNull()
  })

  it('renders the title as a heading', () => {
    render(<StatusState state="unknown" title="Nothing to show" />)
    expect(screen.getByRole('heading', { name: 'Nothing to show' })).toBeInTheDocument()
  })

  it('renders optional description, detail, icon, and action slots', () => {
    render(
      <StatusState
        state="unconfigured"
        title="No cascade"
        description="Load a policy document to populate this grid."
        detail="0 documents resolved"
        icon={<span data-testid="state-icon">⌬</span>}
        action={<button>Open policy editor</button>}
      />,
    )
    expect(screen.getByText('Load a policy document to populate this grid.')).toBeInTheDocument()
    expect(screen.getByText('0 documents resolved')).toBeInTheDocument()
    expect(screen.getByTestId('state-icon')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Open policy editor' })).toBeInTheDocument()
  })

  it('omits every optional slot when not provided', () => {
    render(<StatusState state="not-supported" title="Title only" />)
    const surface = screen.getByTestId('status-state')
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(surface.querySelector('.truth-state__icon')).toBeNull()
    expect(surface.querySelector('.truth-state__description')).toBeNull()
    expect(surface.querySelector('.truth-state__detail')).toBeNull()
  })
})
