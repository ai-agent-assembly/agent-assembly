import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from './auth/AuthProvider'

import { ProtectedRoute } from './pages/ProtectedRoute'
import { LoginPage } from './pages/LoginPage'
import { NotFoundPage } from './pages/NotFoundPage'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function AppRoutes({ initialPath = '/' }: { initialPath?: string }) {
  return (
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<div>Dashboard home</div>} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

beforeEach(() => {
  localStorage.clear()
})

describe('Router smoke tests', () => {
  it('redirects unauthenticated user to /login', () => {
    render(<AppRoutes initialPath="/" />)
    expect(screen.getByRole('heading', { name: 'Agent Assembly' })).toBeInTheDocument()
  })

  it('renders LoginPage at /login', () => {
    render(<AppRoutes initialPath="/login" />)
    expect(screen.getByRole('heading', { name: 'Agent Assembly' })).toBeInTheDocument()
    expect(screen.getByLabelText('API Key')).toBeInTheDocument()
  })

  it('renders NotFoundPage for unknown routes', () => {
    render(<AppRoutes initialPath="/does-not-exist" />)
    expect(screen.getByRole('heading', { name: /404/i })).toBeInTheDocument()
  })

  it('renders protected route when token is present', () => {
    localStorage.setItem('aa_token', 'test-token')
    render(<AppRoutes initialPath="/" />)
    expect(screen.getByText('Dashboard home')).toBeInTheDocument()
  })
})
