import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import type { ReactElement } from 'react'
import { OverviewGuard } from './OverviewPage.guard'
// Inlined at build time by Vite (`?raw`) so the dead-URL guard can read the
// module's own source without node fs access under jsdom.
import guardSource from './OverviewPage.guard.tsx?raw'

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
  toast: vi.fn(),
}

/**
 * The only external URL this module ships, pinned to the exact string that was
 * verified to return 200 with a real request.
 *
 * The first revision of AAASM-5168 replaced a lying link with a dead one:
 * `docs.agent-assembly.com/quickstart` is a 404 and
 * `status.agent-assembly.com` a 530. Asserting the literal here is what makes
 * a silent re-point visible in review — it cannot prove the host is up, so the
 * value must be re-probed if it ever changes.
 */
const INSTALL_DOCS_URL = 'https://docs.agent-assembly.com/core/'

afterEach(() => vi.restoreAllMocks())

describe('OverviewGuard', () => {
  it('renders the loading state while the agents query is loading', () => {
    renderGuard({ ...base, isLoading: true, navigate: vi.fn() })
    expect(screen.getByTestId('loading-state-overview')).toBeInTheDocument()
  })

  it('error state — Retry refetches and the secondary opens no dead status link', () => {
    const navigate = vi.fn()
    const refetch = vi.fn().mockResolvedValue(undefined)
    const toast = vi.fn()
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    renderGuard({ ...base, isError: true, navigate, refetch, toast })
    expect(screen.getByTestId('error-state-generic')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(refetch).toHaveBeenCalledTimes(1)

    // AAASM-5168: this used to route in-app to /audit despite its label, then
    // briefly to status.agent-assembly.com — which answers HTTP 530. The one
    // button a human clicks *during an outage* must not open a dead host.
    fireEvent.click(screen.getByRole('button', { name: /Open status page/ }))
    expect(open).not.toHaveBeenCalled()
    expect(navigate).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith(expect.stringContaining('No status page is available'))
  })

  it('empty state — the CTA opens onboarding and the secondary opens the verified install docs', () => {
    const navigate = vi.fn()
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    renderGuard({ ...base, isEmpty: true, navigate })
    expect(screen.getByTestId('empty-state-overview')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Start setup wizard/ }))
    expect(navigate).toHaveBeenCalledWith('/onboarding')

    // AAASM-5168: this used to land a brand-new operator on an empty Fleet
    // table, and then on a 404 at /quickstart.
    fireEvent.click(screen.getByRole('button', { name: /View install docs/ }))
    expect(open).toHaveBeenCalledWith(INSTALL_DOCS_URL, '_blank', 'noopener,noreferrer')
    expect(navigate).not.toHaveBeenCalledWith('/agents')
  })

  it('ships no URL known to be dead', () => {
    // Both were probed and fail: /quickstart → 404, the status host → 530
    // (ADR 0007 marks status.agent-assembly.com "Future (placeholder)").
    for (const url of [
      'https://status.agent-assembly.com',
      'https://docs.agent-assembly.com/quickstart',
    ]) {
      // Strip comments: this module documents the dead hosts by name so the
      // next reader knows why they are absent.
      const code = guardSource.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
      expect(code).not.toContain(url)
    }
  })

  it('returns null when the fleet has loaded with data (ready)', () => {
    const el = renderGuard({ ...base, navigate: vi.fn() })
    expect(el).toBeNull()
  })
})
