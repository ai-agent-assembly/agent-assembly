import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConfirmDialog } from './ConfirmDialog'

describe('ConfirmDialog', () => {
  it('does not render when open is false', () => {
    render(
      <ConfirmDialog
        open={false}
        title="Discard unsaved changes?"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
  })

  it('renders title + body when open', () => {
    render(
      <ConfirmDialog
        open
        title="Discard unsaved changes?"
        body="Your edits will be lost."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.getByRole('alertdialog')).toHaveAttribute('aria-modal', 'true')
    expect(screen.getByRole('heading', { name: 'Discard unsaved changes?' })).toBeInTheDocument()
    expect(screen.getByText('Your edits will be lost.')).toBeInTheDocument()
  })

  it('uses the default Confirm and Cancel labels', () => {
    render(
      <ConfirmDialog open title="proceed?" onConfirm={() => {}} onCancel={() => {}} />,
    )
    expect(screen.getByTestId('confirm-dialog-confirm')).toHaveTextContent('Confirm')
    expect(screen.getByTestId('confirm-dialog-cancel')).toHaveTextContent('Cancel')
  })

  it('uses custom labels when provided', () => {
    render(
      <ConfirmDialog
        open
        title="proceed?"
        confirmLabel="Discard"
        cancelLabel="Keep editing"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.getByTestId('confirm-dialog-confirm')).toHaveTextContent('Discard')
    expect(screen.getByTestId('confirm-dialog-cancel')).toHaveTextContent('Keep editing')
  })

  it('applies the danger variant class when requested', () => {
    render(
      <ConfirmDialog
        open
        title="delete?"
        confirmVariant="danger"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.getByTestId('confirm-dialog-confirm')).toHaveClass('confirm-dialog__btn--danger')
  })

  it('fires onConfirm when the confirm button is clicked', async () => {
    const user = userEvent.setup()
    const onConfirm = vi.fn()
    render(
      <ConfirmDialog open title="proceed?" onConfirm={onConfirm} onCancel={() => {}} />,
    )
    await user.click(screen.getByTestId('confirm-dialog-confirm'))
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('fires onCancel when the cancel button is clicked', async () => {
    const user = userEvent.setup()
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="proceed?" onConfirm={() => {}} onCancel={onCancel} />,
    )
    await user.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('fires onCancel on backdrop click', async () => {
    const user = userEvent.setup()
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="proceed?" onConfirm={() => {}} onCancel={onCancel} />,
    )
    await user.click(screen.getByTestId('confirm-dialog-backdrop'))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('does not fire onCancel when the dialog body is clicked', async () => {
    const user = userEvent.setup()
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="proceed?" body="msg" onConfirm={() => {}} onCancel={onCancel} />,
    )
    await user.click(screen.getByTestId('confirm-dialog'))
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('fires onCancel on Escape', async () => {
    const user = userEvent.setup()
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="proceed?" onConfirm={() => {}} onCancel={onCancel} />,
    )
    await user.keyboard('{Escape}')
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('focuses the confirm button on open', () => {
    render(
      <ConfirmDialog open title="proceed?" onConfirm={() => {}} onCancel={() => {}} />,
    )
    expect(screen.getByTestId('confirm-dialog-confirm')).toHaveFocus()
  })
})
