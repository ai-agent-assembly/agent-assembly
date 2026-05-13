import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { WindowSeverityRow } from './WindowSeverityRow'

describe('WindowSeverityRow', () => {
  it('renders the current window selection', () => {
    render(
      <WindowSeverityRow
        window="business hours"
        severity="warn"
        onWindowChange={() => {}}
        onSeverityChange={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-window')).toHaveValue('business hours')
  })

  it('marks the active severity pill with aria-checked=true', () => {
    render(
      <WindowSeverityRow
        window="always"
        severity="block"
        onWindowChange={() => {}}
        onSeverityChange={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-severity-block')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('editor-severity-warn')).toHaveAttribute('aria-checked', 'false')
  })

  it('fires onWindowChange on select', async () => {
    const user = userEvent.setup()
    const onWindowChange = vi.fn()
    render(
      <WindowSeverityRow
        window="always"
        severity="warn"
        onWindowChange={onWindowChange}
        onSeverityChange={() => {}}
      />,
    )
    await user.selectOptions(screen.getByTestId('editor-window'), 'weekdays')
    expect(onWindowChange).toHaveBeenCalledWith('weekdays')
  })

  it('fires onSeverityChange on pill click', async () => {
    const user = userEvent.setup()
    const onSeverityChange = vi.fn()
    render(
      <WindowSeverityRow
        window="always"
        severity="warn"
        onWindowChange={() => {}}
        onSeverityChange={onSeverityChange}
      />,
    )
    await user.click(screen.getByTestId('editor-severity-block'))
    expect(onSeverityChange).toHaveBeenCalledWith('block')
  })
})
