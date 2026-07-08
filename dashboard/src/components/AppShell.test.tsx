import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '../auth/AuthProvider'
import { AppShell } from './AppShell'

function Boom(): never {
  throw new Error('child exploded')
}

function renderShell({ child }: { child?: React.ReactNode } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <Routes>
            <Route element={<AppShell />}>
              <Route path="/" element={child ?? <div data-testid="page">page body</div>} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AppShell', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('renders the shell chrome and the routed outlet content', () => {
    renderShell()
    expect(screen.getByTestId('appshell')).toBeInTheDocument()
    expect(screen.getByTestId('appshell-nav')).toBeInTheDocument()
    expect(screen.getByTestId('page')).toHaveTextContent('page body')
  })

  it('shows the logged-in token in the topbar and logs out on click', async () => {
    sessionStorage.setItem('aa_token', 'jwt-123')
    const user = userEvent.setup()
    renderShell()
    expect(screen.getByTestId('appshell-user')).toHaveTextContent('jwt-123')

    await user.click(screen.getByTestId('logout-btn'))
    expect(screen.getByTestId('appshell-user')).toHaveTextContent('')
    expect(sessionStorage.getItem('aa_token')).toBeNull()
  })

  it('toggles the mobile nav open via the hamburger and closes it on nav click', async () => {
    const user = userEvent.setup()
    renderShell()
    const nav = screen.getByTestId('appshell-nav')
    expect(nav.className).not.toContain('appshell__nav--open')

    await user.click(screen.getByTestId('nav-hamburger'))
    expect(nav.className).toContain('appshell__nav--open')

    await user.click(nav)
    expect(nav.className).not.toContain('appshell__nav--open')
  })

  it('catches a render error in the outlet and offers recovery', async () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const user = userEvent.setup()
    renderShell({ child: <Boom /> })

    expect(screen.getByTestId('error-boundary')).toBeInTheDocument()
    expect(screen.getByText('child exploded')).toBeInTheDocument()

    // "Try again" clears the boundary; the child re-throws, so the boundary
    // simply renders the error UI again rather than crashing the app.
    await user.click(screen.getByRole('button', { name: 'Try again' }))
    expect(screen.getByTestId('error-boundary')).toBeInTheDocument()
    errSpy.mockRestore()
  })
})
