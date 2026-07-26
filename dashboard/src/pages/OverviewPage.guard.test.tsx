import { describe, it, expect, vi, afterEach } from 'vitest'
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

afterEach(() => vi.restoreAllMocks())

describe('OverviewGuard', () => {
  it('renders the loading state while the agents query is loading', () => {
    renderGuard({ ...base, isLoading: true, navigate: vi.fn() })
    expect(screen.getByTestId('loading-state-overview')).toBeInTheDocument()
  })

  it('error state — Retry refetches and the secondary opens the real status page', () => {
    const navigate = vi.fn()
    const refetch = vi.fn().mockResolvedValue(undefined)
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    renderGuard({ ...base, isError: true, navigate, refetch })
    expect(screen.getByTestId('error-state-generic')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(refetch).toHaveBeenCalledTimes(1)

    // AAASM-5168: this button used to route in-app to /audit despite its label.
    fireEvent.click(screen.getByRole('button', { name: /Open status page/ }))
    expect(open).toHaveBeenCalledWith(
      'https://status.agent-assembly.com',
      '_blank',
      'noopener,noreferrer',
    )
    expect(navigate).not.toHaveBeenCalled()
  })

  it('empty state — the CTA opens onboarding and the secondary opens the real install docs', () => {
    const navigate = vi.fn()
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    renderGuard({ ...base, isEmpty: true, navigate })
    expect(screen.getByTestId('empty-state-overview')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Start setup wizard/ }))
    expect(navigate).toHaveBeenCalledWith('/onboarding')

    // AAASM-5168: this used to land a brand-new operator on an empty Fleet table.
    fireEvent.click(screen.getByRole('button', { name: /View install docs/ }))
    expect(open).toHaveBeenCalledWith(
      'https://docs.agent-assembly.com/quickstart',
      '_blank',
      'noopener,noreferrer',
    )
    expect(navigate).not.toHaveBeenCalledWith('/agents')
  })

  it('returns null when the fleet has loaded with data (ready)', () => {
    const el = renderGuard({ ...base, navigate: vi.fn() })
    expect(el).toBeNull()
  })
})
