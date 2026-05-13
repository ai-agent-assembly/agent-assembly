import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ActionPicker } from './ActionPicker'

describe('ActionPicker', () => {
  it('renders all 5 action buttons with the hint as a tooltip title', () => {
    render(<ActionPicker value="allow" onChange={() => {}} />)
    expect(screen.getByTestId('editor-action-allow')).toHaveAttribute('title', 'pass through')
    expect(screen.getByTestId('editor-action-narrow')).toHaveAttribute('title', 'restrict scope')
    expect(screen.getByTestId('editor-action-approval')).toHaveAttribute('title', 'human review')
    expect(screen.getByTestId('editor-action-scrub-then-allow')).toHaveAttribute(
      'title',
      'redact PII first',
    )
    expect(screen.getByTestId('editor-action-deny')).toHaveAttribute('title', 'block')
  })

  it('marks the matching button with aria-checked=true', () => {
    render(<ActionPicker value="approval" onChange={() => {}} />)
    expect(screen.getByTestId('editor-action-approval')).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByTestId('editor-action-allow')).toHaveAttribute('aria-checked', 'false')
  })

  it('fires onChange with the clicked action id', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<ActionPicker value="allow" onChange={onChange} />)
    await user.click(screen.getByTestId('editor-action-deny'))
    expect(onChange).toHaveBeenCalledWith('deny')
  })
})
