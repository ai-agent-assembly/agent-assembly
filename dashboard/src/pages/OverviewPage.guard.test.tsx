import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import type { ReactElement } from 'react'
import { OverviewGuard } from './OverviewPage.guard'

/**
 * Render whatever the guard returns. The guard is a plain function returning a
 * `ReactElement | null`, so we invoke it directly and only mount when it yields
 * an element — exercising each branch (loading / error / empty / ready) and the
 * wired-up callbacks in isolation from the full Overview page.
 */
function renderGuard(args: Parameters<typeof OverviewGuard>[0]): ReactElement | null {
  const el = OverviewGuard(args)
  if (el) render(el)
  return el
}

const base = {
  isLoading: false,
  isError: false,
  isEmpty: false,
  navigate: vi.fn(),
  refetch: vi.fn().mockResolvedValue(undefined),
}

describe('OverviewGuard', () => {
  it('renders the loading state while the agents query is loading', () => {
    renderGuard({ ...base, isLoading: true, navigate: vi.fn() })
    expect(screen.getByTestId('loading-state-overview')).toBeInTheDocument()
  })

  it('error state — Retry refetches and the secondary action opens the audit log', () => {
    const navigate = vi.fn()
    const refetch = vi.fn().mockResolvedValue(undefined)
    renderGuard({ ...base, isError: true, navigate, refetch })
    expect(screen.getByTestId('error-state-generic')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(refetch).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /Open status page/ }))
    expect(navigate).toHaveBeenCalledWith('/audit')
  })

  it('empty state — the CTA opens onboarding and the secondary opens the fleet', () => {
    const navigate = vi.fn()
    renderGuard({ ...base, isEmpty: true, navigate })
    expect(screen.getByTestId('empty-state-overview')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Start setup wizard/ }))
    expect(navigate).toHaveBeenCalledWith('/onboarding')
    fireEvent.click(screen.getByRole('button', { name: /View install docs/ }))
    expect(navigate).toHaveBeenCalledWith('/agents')
  })

  it('returns null when the fleet has loaded with data (ready)', () => {
    const el = renderGuard({ ...base, navigate: vi.fn() })
    expect(el).toBeNull()
  })
})
