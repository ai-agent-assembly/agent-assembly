import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LoginPage } from './LoginPage'
import * as useAuthModule from '../auth/useAuth'

function renderLogin(login: ReturnType<typeof vi.fn>) {
  vi.spyOn(useAuthModule, 'useAuth').mockReturnValue({
    token: null,
    login,
    logout: vi.fn(),
  })
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<div data-testid="home">home</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('LoginPage', () => {
  it('disables the submit button until an api key is entered', () => {
    renderLogin(vi.fn())
    const button = screen.getByRole('button', { name: 'Sign in' })
    expect(button).toBeDisabled()
    fireEvent.change(screen.getByLabelText('API Key'), { target: { value: 'aa_key' } })
    expect(button).not.toBeDisabled()
  })

  it('logs in with the trimmed key and navigates home on success', async () => {
    const login = vi.fn().mockResolvedValue(undefined)
    renderLogin(login)
    fireEvent.change(screen.getByLabelText('API Key'), { target: { value: '  aa_key  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(login).toHaveBeenCalledWith('aa_key'))
    await waitFor(() => expect(screen.getByTestId('home')).toBeInTheDocument())
  })

  it('shows an error message and stays on the page when login fails', async () => {
    const login = vi.fn().mockRejectedValue(new Error('Authentication failed (401)'))
    renderLogin(login)
    fireEvent.change(screen.getByLabelText('API Key'), { target: { value: 'aa_bad' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() =>
      expect(screen.getByText(/Authentication failed \(401\)/)).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('home')).not.toBeInTheDocument()
    // Button label resets after the failed attempt.
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })
})
