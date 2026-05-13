import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TraceDrawer } from './TraceDrawer'
import { TraceDrawerProvider } from './TraceDrawerProvider'
import { useTraceDrawer } from './useTraceDrawer'

// Mock the lazy-loaded page so the drawer test doesn't need QueryClient + Router.
vi.mock('../../pages/TraceViewPage', () => ({
  TraceViewPage: ({ agentId, sessionId }: { agentId: string; sessionId: string }) => (
    <div data-testid="trace-view-stub">
      <span data-testid="trace-view-agent">{agentId}</span>
      <span data-testid="trace-view-session">{sessionId}</span>
      <button type="button" data-testid="stub-action">Action</button>
    </div>
  ),
}))

function Opener({ agentId, sessionId, label }: { agentId: string; sessionId: string; label: string }) {
  const { open } = useTraceDrawer()
  return (
    <button type="button" onClick={() => open(agentId, sessionId)}>
      {label}
    </button>
  )
}

function Harness({ openers }: { openers: Array<{ agentId: string; sessionId: string; label: string }> }) {
  return (
    <TraceDrawerProvider>
      {openers.map(o => (
        <Opener key={o.label} {...o} />
      ))}
      <TraceDrawer />
    </TraceDrawerProvider>
  )
}

async function findTraceView() {
  return await screen.findByTestId('trace-view-stub')
}

describe('TraceDrawer', () => {
  it('is hidden by default and not rendered in the DOM', () => {
    render(<Harness openers={[{ agentId: 'a1', sessionId: 's1', label: 'open' }]} />)
    expect(screen.queryByTestId('trace-drawer')).not.toBeInTheDocument()
  })

  it('opens with the given agentId / sessionId and renders the trace view body', async () => {
    const user = userEvent.setup()
    render(<Harness openers={[{ agentId: 'support-bot', sessionId: 'sess-42', label: 'open' }]} />)

    await user.click(screen.getByText('open'))

    expect(await screen.findByTestId('trace-drawer')).toBeInTheDocument()
    await findTraceView()
    expect(screen.getByTestId('trace-view-agent')).toHaveTextContent('support-bot')
    expect(screen.getByTestId('trace-view-session')).toHaveTextContent('sess-42')
  })

  it('closes when the Esc key is pressed', async () => {
    const user = userEvent.setup()
    render(<Harness openers={[{ agentId: 'a', sessionId: 's', label: 'open' }]} />)

    await user.click(screen.getByText('open'))
    await screen.findByTestId('trace-drawer')

    await user.keyboard('{Escape}')

    await waitFor(() => {
      expect(screen.queryByTestId('trace-drawer')).not.toBeInTheDocument()
    })
  })

  it('closes when the scrim (backdrop) is clicked', async () => {
    const user = userEvent.setup()
    render(<Harness openers={[{ agentId: 'a', sessionId: 's', label: 'open' }]} />)

    await user.click(screen.getByText('open'))
    await screen.findByTestId('trace-drawer')

    await user.click(screen.getByTestId('trace-drawer-scrim'))

    await waitFor(() => {
      expect(screen.queryByTestId('trace-drawer')).not.toBeInTheDocument()
    })
  })

  it('does not close when clicking inside the drawer body', async () => {
    const user = userEvent.setup()
    render(<Harness openers={[{ agentId: 'a', sessionId: 's', label: 'open' }]} />)

    await user.click(screen.getByText('open'))
    await findTraceView()

    await user.click(screen.getByTestId('trace-view-stub'))
    expect(screen.getByTestId('trace-drawer')).toBeInTheDocument()
  })

  it('closes when the close button is clicked', async () => {
    const user = userEvent.setup()
    render(<Harness openers={[{ agentId: 'a', sessionId: 's', label: 'open' }]} />)

    await user.click(screen.getByText('open'))
    await screen.findByTestId('trace-drawer')

    await user.click(screen.getByTestId('trace-drawer-close'))

    await waitFor(() => {
      expect(screen.queryByTestId('trace-drawer')).not.toBeInTheDocument()
    })
  })

  it('focuses the close button when opened (focus trap entry point)', async () => {
    const user = userEvent.setup()
    render(<Harness openers={[{ agentId: 'a', sessionId: 's', label: 'open' }]} />)

    await user.click(screen.getByText('open'))
    await screen.findByTestId('trace-drawer')

    await waitFor(() => {
      expect(screen.getByTestId('trace-drawer-close')).toHaveFocus()
    })
  })

  it('replaces ids when open() is called a second time with different ids', async () => {
    const user = userEvent.setup()
    render(
      <Harness
        openers={[
          { agentId: 'agent-a', sessionId: 'sess-a', label: 'open-a' },
          { agentId: 'agent-b', sessionId: 'sess-b', label: 'open-b' },
        ]}
      />,
    )

    await user.click(screen.getByText('open-a'))
    await findTraceView()
    expect(screen.getByTestId('trace-view-agent')).toHaveTextContent('agent-a')

    // Open again with new ids — drawer must update to the new agent/session.
    await user.click(screen.getByText('open-b'))
    await waitFor(() => {
      expect(screen.getByTestId('trace-view-agent')).toHaveTextContent('agent-b')
    })
    expect(screen.getByTestId('trace-view-session')).toHaveTextContent('sess-b')
  })

  it('throws when useTraceDrawer is used outside the provider', () => {
    // Silence the React error boundary console output for this expected failure.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => render(<Opener agentId="a" sessionId="s" label="x" />)).toThrow(
      /useTraceDrawer must be used inside <TraceDrawerProvider>/,
    )
    spy.mockRestore()
  })
})
