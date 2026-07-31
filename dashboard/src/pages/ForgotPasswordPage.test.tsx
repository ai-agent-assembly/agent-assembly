import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ForgotPasswordPage } from './ForgotPasswordPage'
import * as authApi from '../auth/authApi'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/login" element={<div data-testid="login">login</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ForgotPasswordPage — request', () => {
  it('shows the neutral enumeration-safe message after submitting an email', async () => {
    vi.spyOn(authApi, 'requestPasswordReset').mockResolvedValue(undefined)
    renderAt('/forgot-password')

    fireEvent.change(screen.getByLabelText('Work email'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send reset link' }))

    expect(await screen.findByRole('status')).toHaveTextContent(/if that email matches an account/i)
  })

  it('shows the same neutral message even when the request throws', async () => {
    vi.spyOn(authApi, 'requestPasswordReset').mockRejectedValue(new Error('boom'))
    renderAt('/forgot-password')

    fireEvent.change(screen.getByLabelText('Work email'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send reset link' }))

    expect(await screen.findByRole('status')).toHaveTextContent(/if that email matches an account/i)
  })
})

describe('ForgotPasswordPage — confirm', () => {
  it('opens the confirm form when the URL carries a token', () => {
    renderAt('/forgot-password?token=abc123')
    expect(screen.getByLabelText('Reset token')).toHaveValue('abc123')
    expect(screen.getByLabelText('New password')).toBeInTheDocument()
  })

  it('confirms the reset and shows the sign-in link on success', async () => {
    const confirm = vi.spyOn(authApi, 'confirmPasswordReset').mockResolvedValue(undefined)
    renderAt('/forgot-password?token=abc123')

    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'newpass12' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reset password' }))

    await waitFor(() => expect(confirm).toHaveBeenCalledWith('abc123', 'newpass12'))
    expect(await screen.findByRole('status')).toHaveTextContent(/your password has been reset/i)
  })

  it('rejects a short password before calling the backend', async () => {
    const confirm = vi.spyOn(authApi, 'confirmPasswordReset').mockResolvedValue(undefined)
    renderAt('/forgot-password?token=abc123')

    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'short' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reset password' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/at least 8 characters/i)
    expect(confirm).not.toHaveBeenCalled()
  })

  it('surfaces an expired-token error from the backend', async () => {
    vi.spyOn(authApi, 'confirmPasswordReset').mockRejectedValue(
      new authApi.AuthApiError('This reset link has expired or already been used.', 422),
    )
    renderAt('/forgot-password?token=stale')

    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'newpass12' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reset password' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/expired or already been used/i)
  })
})
