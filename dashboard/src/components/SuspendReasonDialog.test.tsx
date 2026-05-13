import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { SuspendReasonDialog } from './SuspendReasonDialog'

describe('SuspendReasonDialog', () => {
  it('renders the default title and body text', () => {
    render(<SuspendReasonDialog onConfirm={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByText('Suspend agent')).toBeInTheDocument()
    expect(screen.getByLabelText(/Reason/)).toBeInTheDocument()
  })

  it('honours custom title + body when provided', () => {
    render(
      <SuspendReasonDialog
        title="Suspend 3 agents"
        body="The reason is logged once for the entire batch."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    expect(screen.getByText('Suspend 3 agents')).toBeInTheDocument()
    expect(screen.getByText(/logged once/)).toBeInTheDocument()
  })

  it('keeps the submit button disabled when the textarea is empty', () => {
    render(<SuspendReasonDialog onConfirm={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByTestId('suspend-dialog-confirm')).toBeDisabled()
  })

  it('enables submit and fires onConfirm with the trimmed reason', () => {
    const onConfirm = vi.fn()
    render(<SuspendReasonDialog onConfirm={onConfirm} onCancel={vi.fn()} />)
    fireEvent.change(screen.getByTestId('suspend-dialog-input'), { target: { value: '  budget exceeded  ' } })
    expect(screen.getByTestId('suspend-dialog-confirm')).not.toBeDisabled()
    fireEvent.click(screen.getByTestId('suspend-dialog-confirm'))
    expect(onConfirm).toHaveBeenCalledTimes(1)
    expect(onConfirm).toHaveBeenCalledWith('budget exceeded')
  })

  it('shows a validation message on blur when the reason is empty', () => {
    render(<SuspendReasonDialog onConfirm={vi.fn()} onCancel={vi.fn()} />)
    const input = screen.getByTestId('suspend-dialog-input')
    fireEvent.blur(input)
    expect(screen.getByTestId('suspend-dialog-error')).toBeInTheDocument()
  })

  it('does not fire onConfirm when the form is submitted with an empty reason', () => {
    const onConfirm = vi.fn()
    render(<SuspendReasonDialog onConfirm={onConfirm} onCancel={vi.fn()} />)
    fireEvent.submit(screen.getByTestId('suspend-dialog'))
    expect(onConfirm).not.toHaveBeenCalled()
    expect(screen.getByTestId('suspend-dialog-error')).toBeInTheDocument()
  })

  it('fires onCancel when the cancel button is clicked', () => {
    const onCancel = vi.fn()
    render(<SuspendReasonDialog onConfirm={vi.fn()} onCancel={onCancel} />)
    fireEvent.click(screen.getByTestId('suspend-dialog-cancel'))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('fires onCancel on Escape and scrim click', () => {
    const onCancel = vi.fn()
    render(<SuspendReasonDialog onConfirm={vi.fn()} onCancel={onCancel} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onCancel).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByTestId('suspend-dialog-scrim'))
    expect(onCancel).toHaveBeenCalledTimes(2)
  })

  it('shows a working label and disables submit when pending is true', () => {
    render(<SuspendReasonDialog pending onConfirm={vi.fn()} onCancel={vi.fn()} />)
    const submit = screen.getByTestId('suspend-dialog-confirm')
    expect(submit).toHaveTextContent(/Suspending/)
    expect(submit).toBeDisabled()
  })
})
