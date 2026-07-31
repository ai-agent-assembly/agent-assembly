import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, vi } from 'vitest'
import { AuthProvider } from './auth/AuthProvider'
import * as authApi from './auth/authApi'

import { ProtectedRoute } from './pages/ProtectedRoute'
import { LoginPage } from './pages/LoginPage'
import { NotFoundPage } from './pages/NotFoundPage'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

// Mirrors App.tsx's "/" → "/overview" redirect (AAASM-5144) without pulling in
// OverviewPage's full data-fetching stack — this smoke test only cares that
// root lands on the Overview route, not on Overview's own rendered content.
function AppRoutes({ initialPath = '/' }: Readonly<{ initialPath?: string }>) {
  return (
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<div>Overview page</div>} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

beforeEach(() => {
  sessionStorage.clear()
  localStorage.clear()
  // The login page reads the auth-methods signal on mount; keep the smoke test
  // deterministic (in-memory deployment) rather than hitting the real client.
  vi.spyOn(authApi, 'authMethods').mockResolvedValue(['api_key'])
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Router smoke tests', () => {
  it('redirects unauthenticated user to /login', async () => {
    render(<AppRoutes initialPath="/" />)
    expect(await screen.findByRole('heading', { name: 'Agent Assembly' })).toBeInTheDocument()
  })

  it('renders LoginPage at /login', async () => {
    render(<AppRoutes initialPath="/login" />)
    expect(await screen.findByRole('heading', { name: 'Agent Assembly' })).toBeInTheDocument()
    expect(screen.getByLabelText('API key')).toBeInTheDocument()
  })

  it('renders NotFoundPage for unknown routes', () => {
    render(<AppRoutes initialPath="/does-not-exist" />)
    expect(screen.getByRole('heading', { name: /404/i })).toBeInTheDocument()
  })

  it('renders protected route when token is present', () => {
    sessionStorage.setItem('aa_token', 'test-token')
    render(<AppRoutes initialPath="/" />)
    expect(screen.getByText('Overview page')).toBeInTheDocument()
  })
})
