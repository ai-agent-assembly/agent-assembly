import { render, screen, fireEvent } from '@testing-library/react'
import { PanelErrorBoundary } from './PanelErrorBoundary'

// A component that throws on render, gated by a module-level flag so we can
// let a retry re-render succeed.
let shouldThrow = true
function Boom() {
  if (shouldThrow) throw new Error('Invalid time value')
  return <div data-testid="boom-recovered">recovered</div>
}

describe('PanelErrorBoundary', () => {
  beforeEach(() => {
    shouldThrow = true
    // React + the boundary log the caught error; silence to keep test output clean.
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders children when they do not throw', () => {
    shouldThrow = false
    render(
      <PanelErrorBoundary panelName="Action Volume">
        <Boom />
      </PanelErrorBoundary>,
    )
    expect(screen.getByTestId('boom-recovered')).toBeInTheDocument()
    expect(screen.queryByTestId('error-state')).not.toBeInTheDocument()
  })

  it('shows a single-panel error card when a child throws', () => {
    render(
      <PanelErrorBoundary panelName="Action Volume">
        <Boom />
      </PanelErrorBoundary>,
    )
    expect(screen.getByTestId('error-state')).toBeInTheDocument()
    expect(screen.getByText(/Action Volume couldn't be displayed/)).toBeInTheDocument()
  })

  it('isolates a failing panel from sibling panels', () => {
    render(
      <div>
        <PanelErrorBoundary panelName="Action Volume">
          <Boom />
        </PanelErrorBoundary>
        <PanelErrorBoundary panelName="Cost Breakdown">
          <div data-testid="healthy-sibling">still here</div>
        </PanelErrorBoundary>
      </div>,
    )
    // The bad panel degrades to an error card...
    expect(screen.getByText(/Action Volume couldn't be displayed/)).toBeInTheDocument()
    // ...while the sibling panel keeps rendering (no whole-view blank).
    expect(screen.getByTestId('healthy-sibling')).toBeInTheDocument()
  })

  it('recovers when "Try again" is clicked and the child no longer throws', () => {
    render(
      <PanelErrorBoundary panelName="Action Volume">
        <Boom />
      </PanelErrorBoundary>,
    )
    expect(screen.getByTestId('error-state')).toBeInTheDocument()

    shouldThrow = false
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))

    expect(screen.getByTestId('boom-recovered')).toBeInTheDocument()
    expect(screen.queryByTestId('error-state')).not.toBeInTheDocument()
  })
})
