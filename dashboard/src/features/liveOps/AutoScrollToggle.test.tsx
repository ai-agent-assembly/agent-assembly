import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AutoScrollToggle } from './AutoScrollToggle'

function StaticHarness(props: {
  enabled: boolean
  pendingCount: number
  onEnabledChange?: (v: boolean) => void
  onFlushPending?: () => void
}) {
  return (
    <AutoScrollToggle
      enabled={props.enabled}
      onEnabledChange={props.onEnabledChange ?? (() => {})}
      pendingCount={props.pendingCount}
      onFlushPending={props.onFlushPending ?? (() => {})}
    />
  )
}

function ControlledHarness({
  initialEnabled,
  initialPending,
}: {
  initialEnabled: boolean
  initialPending: number
}) {
  const [enabled, setEnabled] = useState(initialEnabled)
  const [pending, setPending] = useState(initialPending)
  return (
    <AutoScrollToggle
      enabled={enabled}
      onEnabledChange={setEnabled}
      pendingCount={pending}
      onFlushPending={() => setPending(0)}
    />
  )
}

describe('AutoScrollToggle', () => {
  it('renders the on state with the "Auto-scroll" label', () => {
    render(<StaticHarness enabled pendingCount={0} />)
    const root = screen.getByTestId('auto-scroll-toggle')
    expect(root).toHaveAttribute('data-enabled', 'true')
    expect(screen.getByText('Auto-scroll')).toBeInTheDocument()
    expect(screen.queryByTestId('auto-scroll-flush')).toBeNull()
  })

  it('renders the paused state with the "Paused" label and no pill when empty', () => {
    render(<StaticHarness enabled={false} pendingCount={0} />)
    expect(screen.getByTestId('auto-scroll-toggle')).toHaveAttribute(
      'data-enabled',
      'false',
    )
    expect(screen.getByText('Paused')).toBeInTheDocument()
    expect(screen.queryByTestId('auto-scroll-flush')).toBeNull()
  })

  it('shows the pending pill only when paused with backlog', () => {
    const { rerender } = render(<StaticHarness enabled pendingCount={5} />)
    expect(screen.queryByTestId('auto-scroll-flush')).toBeNull()

    rerender(<StaticHarness enabled={false} pendingCount={5} />)
    const pill = screen.getByTestId('auto-scroll-flush')
    expect(pill).toBeInTheDocument()
    expect(pill).toHaveTextContent('5 new ops — flush')
  })

  it('uses singular "op" when exactly one event is buffered', () => {
    render(<StaticHarness enabled={false} pendingCount={1} />)
    expect(screen.getByTestId('auto-scroll-flush')).toHaveTextContent(
      '1 new op — flush',
    )
  })

  it('emits onEnabledChange when the switch is toggled', async () => {
    const user = userEvent.setup()
    const onEnabledChange = vi.fn()
    render(
      <StaticHarness
        enabled={false}
        pendingCount={0}
        onEnabledChange={onEnabledChange}
      />,
    )
    await user.click(screen.getByTestId('auto-scroll-toggle-input'))
    expect(onEnabledChange).toHaveBeenCalledWith(true)
  })

  it('flushes the backlog and hides the pill once cleared', async () => {
    const user = userEvent.setup()
    render(<ControlledHarness initialEnabled={false} initialPending={3} />)
    const pill = screen.getByTestId('auto-scroll-flush')
    expect(pill).toHaveTextContent('3 new ops — flush')

    await user.click(pill)
    expect(screen.queryByTestId('auto-scroll-flush')).toBeNull()
  })

  it('exposes the enabled state via the checkbox input', () => {
    const { rerender } = render(<StaticHarness enabled pendingCount={0} />)
    const input = screen.getByTestId('auto-scroll-toggle-input') as HTMLInputElement
    expect(input.type).toBe('checkbox')
    expect(input.checked).toBe(true)
    rerender(<StaticHarness enabled={false} pendingCount={0} />)
    expect(input.checked).toBe(false)
  })
})
