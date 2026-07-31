import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LoginPage } from './LoginPage'
import * as useAuthModule from '../auth/useAuth'
import * as authApi from '../auth/authApi'
import type { AuthContextValue } from '../auth/AuthContext'

function mockAuth(overrides: Partial<AuthContextValue> = {}) {
  vi.spyOn(useAuthModule, 'useAuth').mockReturnValue({
    token: null,
    scopes: [],
    login: vi.fn().mockResolvedValue(undefined),
    loginWithCredentials: vi.fn().mockResolvedValue(undefined),
    signup: vi.fn().mockResolvedValue(undefined),
    logout: vi.fn(),
    ...overrides,
  })
}

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<div data-testid="home">home</div>} />
        <Route path="/forgot-password" element={<div data-testid="forgot">forgot</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('LoginPage — honest degradation (ADR 0031 §Q5)', () => {
  it('renders API-key-only with a note when the backend advertises only api_key', async () => {
    mockAuth()
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key'])
    renderLogin()

    expect(await screen.findByLabelText('API key')).toBeInTheDocument()
    expect(screen.getByText(/needs a Postgres-backed deployment/i)).toBeInTheDocument()
    // No password form and no sign-up tab on an in-memory deployment.
    expect(screen.queryByRole('tab', { name: 'Sign up' })).not.toBeInTheDocument()
  })

  it('renders the two-tab email/password UI when password auth is enabled', async () => {
    mockAuth()
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    expect(await screen.findByRole('tab', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Sign up' })).toBeInTheDocument()
    expect(screen.getByLabelText('Work email')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    // API-key path is still reachable, behind a toggle.
    expect(
      screen.getByRole('button', { name: /Sign in with an API key instead/i }),
    ).toBeInTheDocument()
  })

  it('never renders OAuth/social affordances (D4)', async () => {
    mockAuth()
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    await screen.findByRole('tab', { name: 'Sign in' })
    expect(screen.queryByText(/Continue with Google/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/Continue with GitHub/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/or continue with email/i)).not.toBeInTheDocument()
  })
})

describe('LoginPage — credential flows', () => {
  it('signs in with trimmed email + password and navigates home', async () => {
    const loginWithCredentials = vi.fn().mockResolvedValue(undefined)
    mockAuth({ loginWithCredentials })
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    fireEvent.change(await screen.findByLabelText('Work email'), {
      target: { value: '  user@example.com  ' },
    })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2!' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() =>
      expect(loginWithCredentials).toHaveBeenCalledWith('user@example.com', 'hunter2!', false),
    )
    expect(await screen.findByTestId('home')).toBeInTheDocument()
  })

  it('creates an account on the sign-up tab', async () => {
    const signup = vi.fn().mockResolvedValue(undefined)
    mockAuth({ signup })
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    fireEvent.click(await screen.findByRole('tab', { name: 'Sign up' }))
    fireEvent.change(screen.getByLabelText('Work email'), { target: { value: 'new@example.com' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2!' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }))

    await waitFor(() => expect(signup).toHaveBeenCalledWith('new@example.com', 'hunter2!'))
    expect(await screen.findByTestId('home')).toBeInTheDocument()
  })

  it('rejects a short password before calling the backend', async () => {
    const loginWithCredentials = vi.fn().mockResolvedValue(undefined)
    mockAuth({ loginWithCredentials })
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    fireEvent.change(await screen.findByLabelText('Work email'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'short' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/at least 8 characters/i)
    expect(loginWithCredentials).not.toHaveBeenCalled()
  })

  it('surfaces the AuthApiError message on a failed sign-in', async () => {
    const loginWithCredentials = vi
      .fn()
      .mockRejectedValue(new authApi.AuthApiError('Invalid email or password.', 401))
    mockAuth({ loginWithCredentials })
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    fireEvent.change(await screen.findByLabelText('Work email'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2!' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password.')
    expect(screen.queryByTestId('home')).not.toBeInTheDocument()
  })

  it('links to the forgot-password flow from the sign-in tab', async () => {
    mockAuth()
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key', 'password'])
    renderLogin()

    fireEvent.click(await screen.findByRole('link', { name: 'Forgot?' }))
    expect(await screen.findByTestId('forgot')).toBeInTheDocument()
  })
})

describe('LoginPage — API-key path', () => {
  it('logs in with the trimmed key and navigates home (in-memory deployment)', async () => {
    const login = vi.fn().mockResolvedValue(undefined)
    mockAuth({ login })
    vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key'])
    renderLogin()

    fireEvent.change(await screen.findByLabelText('API key'), { target: { value: '  aa_key  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with API key' }))

    await waitFor(() => expect(login).toHaveBeenCalledWith('aa_key'))
    expect(await screen.findByTestId('home')).toBeInTheDocument()
  })

  it('falls back to the API-key path when the methods probe fails', async () => {
    mockAuth()
    vi.spyOn(authApi, 'authMethods').mockRejectedValue(new Error('network'))
    renderLogin()

    expect(await screen.findByLabelText('API key')).toBeInTheDocument()
  })
})
