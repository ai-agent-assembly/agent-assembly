import { render, screen, act, renderHook } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from './AppShell'
import { OverlayProvider } from './OverlayProvider'
import { useOverlay } from './useOverlay'
import { OVERLAY_NAMES } from './OverlayContext'
import { AuthProvider } from '../auth/AuthProvider'
import { CANONICAL_ROUTES, ROUTE_GROUPS } from '../routes'

function withQueryClient(children: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('OverlayProvider + useOverlay', () => {
  function wrapper({ children }: { children: React.ReactNode }) {
    return <OverlayProvider>{children}</OverlayProvider>
  }

  it('exposes one entry per OVERLAY_NAMES with open=false by default', () => {
    const hooks = OVERLAY_NAMES.map((name) =>
      renderHook(() => useOverlay(name), { wrapper }),
    )
    hooks.forEach(({ result }) => {
      expect(result.current.open).toBe(false)
      expect(result.current.props).toEqual({})
    })
  })

  it('openOverlay flips open to true and passes props through', () => {
    const { result } = renderHook(() => useOverlay('tweaks'), { wrapper })
    expect(result.current.open).toBe(false)
    act(() => result.current.openOverlay({ source: 'unit-test' }))
    expect(result.current.open).toBe(true)
    expect(result.current.props).toEqual({ source: 'unit-test' })
  })

  it('closeOverlay resets the entry back to closed with empty props', () => {
    const { result } = renderHook(() => useOverlay('trace'), { wrapper })
    act(() => result.current.openOverlay({ traceId: 'abc' }))
    expect(result.current.open).toBe(true)
    act(() => result.current.closeOverlay())
    expect(result.current.open).toBe(false)
    expect(result.current.props).toEqual({})
  })

  it('overlays are independent — opening one does not affect siblings', () => {
    const tweaks = renderHook(() => useOverlay('tweaks'), { wrapper })
    const alerts = renderHook(() => useOverlay('alerts'), { wrapper })
    act(() => tweaks.result.current.openOverlay())
    expect(tweaks.result.current.open).toBe(true)
    expect(alerts.result.current.open).toBe(false)
  })

  it('useOverlay throws when used outside an OverlayProvider', () => {
    expect(() => renderHook(() => useOverlay('alerts'))).toThrow(
      /useOverlay must be used within an OverlayProvider/,
    )
  })

  it('OverlayProvider renders its children', () => {
    render(
      <OverlayProvider>
        <span data-testid="child">hello</span>
      </OverlayProvider>,
    )
    expect(screen.getByTestId('child')).toHaveTextContent('hello')
  })
})

describe('AppShell overlay mount points', () => {
  it('renders one <div data-overlay={name}> per OVERLAY_NAMES entry', () => {
    localStorage.setItem('aa_token', 'test-token')
    render(withQueryClient(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <Routes>
            <Route element={<AppShell />}>
              <Route path="/" element={<div>page</div>} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    ))
    for (const name of OVERLAY_NAMES) {
      const mount = screen.getByTestId(`overlay-mount-${name}`)
      expect(mount).toBeInTheDocument()
      expect(mount.getAttribute('data-overlay')).toBe(name)
    }
    localStorage.clear()
  })
})

describe('AppShell canonical nav', () => {
  function renderShell() {
    localStorage.setItem('aa_token', 'test-token')
    render(withQueryClient(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <Routes>
            <Route element={<AppShell />}>
              <Route path="/" element={<div>page</div>} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    ))
    return () => localStorage.clear()
  }

  it('renders one nav-link-{id} per CANONICAL_ROUTES entry', () => {
    const cleanup = renderShell()
    for (const r of CANONICAL_ROUTES) {
      expect(screen.getByTestId(`nav-link-${r.id}`)).toBeInTheDocument()
    }
    cleanup()
  })

  it('groups the nav into monitor / control / manage sections', () => {
    const cleanup = renderShell()
    for (const group of ROUTE_GROUPS) {
      expect(screen.getByTestId(`nav-group-${group}`)).toBeInTheDocument()
      expect(screen.getByTestId(`nav-section-${group}`)).toBeInTheDocument()
    }
    cleanup()
  })
})
