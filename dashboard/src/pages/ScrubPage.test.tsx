import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ScrubPage } from './ScrubPage'
import { ToastProvider } from '../components/ToastProvider'
import { PATTERNS } from '../features/scrub/fixtures'

const TOTAL = PATTERNS.length
const ENABLED = PATTERNS.filter((p) => p.enabled).length
const TOTAL_HITS = PATTERNS.filter((p) => p.enabled).reduce((s, p) => s + p.hits24h, 0)

describe('ScrubPage', () => {
  it('renders the header with enabled-count and total-hits derived from the patterns', () => {
    render(<ScrubPage />)
    expect(screen.getByTestId('scrub-page')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-page-sub')).toHaveTextContent(
      `${ENABLED} of ${TOTAL} patterns active`,
    )
    expect(screen.getByTestId('scrub-stats-stripped')).toHaveTextContent(
      `${TOTAL_HITS} stripped / 24h`,
    )
    expect(screen.getByTestId('scrub-stats-enabled-count')).toHaveTextContent(
      `${ENABLED}/${TOTAL} patterns enabled`,
    )
  })

  it('toggling a pattern off updates the enabled count and stripped-hits total', () => {
    render(<ScrubPage />)
    // OPENAI_KEY is enabled by default with 22 hits.
    const openai = PATTERNS.find((p) => p.id === 'OPENAI_KEY')!
    fireEvent.click(screen.getByTestId('scrub-patterns-toggle-OPENAI_KEY'))
    expect(screen.getByTestId('scrub-stats-enabled-count')).toHaveTextContent(
      `${ENABLED - 1}/${TOTAL} patterns enabled`,
    )
    expect(screen.getByTestId('scrub-stats-stripped')).toHaveTextContent(
      `${TOTAL_HITS - openai.hits24h} stripped / 24h`,
    )
  })

  it('selecting a different pattern updates the detail panel', () => {
    render(<ScrubPage />)
    const target = PATTERNS.find((p) => p.id !== 'OPENAI_KEY')!
    fireEvent.click(screen.getByTestId(`scrub-patterns-row-${target.id}`))
    expect(screen.getByTestId('scrub-detail')).toHaveTextContent(target.name)
  })

  it('collapsing the pattern detail flips its data-collapsed flag', () => {
    render(<ScrubPage />)
    const detail = screen.getByTestId('scrub-detail')
    expect(detail).toHaveAttribute('data-collapsed', 'false')
    fireEvent.click(screen.getByTestId('scrub-detail-collapse'))
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'true')
  })

  it('renders the header action buttons and the covers / policy stat segments', () => {
    render(<ScrubPage />)
    expect(screen.getByTestId('scrub-add-pattern')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-export-config')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-stats-covers')).toHaveTextContent(
      'http egress · gmail · slack',
    )
    expect(screen.getByTestId('scrub-stats-policy')).toHaveTextContent('P-100')
  })

  it('disabling the selected pattern from the detail row drops the enabled count', () => {
    render(<ScrubPage />)
    // OPENAI_KEY is selected and enabled by default.
    fireEvent.click(screen.getByTestId('scrub-detail-disable'))
    expect(screen.getByTestId('scrub-stats-enabled-count')).toHaveTextContent(
      `${ENABLED - 1}/${TOTAL} patterns enabled`,
    )
  })

  it('all "coming soon" affordances no-op (do not throw) without a ToastProvider', () => {
    // Rendered without a provider, `toast` is null and every handler must take
    // the optional-chaining short-circuit rather than crash the page.
    render(<ScrubPage />)
    fireEvent.click(screen.getByTestId('scrub-add-pattern'))
    fireEvent.click(screen.getByTestId('scrub-export-config'))
    fireEvent.click(screen.getByTestId('scrub-detail-edit'))
    fireEvent.click(screen.getByTestId('scrub-detail-test'))
    // No toast surface exists, and the page is still mounted.
    expect(screen.queryByTestId('toast')).toBeNull()
    expect(screen.getByTestId('scrub-page')).toBeInTheDocument()
  })

  describe('inside a ToastProvider', () => {
    const renderWithToast = () =>
      render(
        <ToastProvider>
          <ScrubPage />
        </ToastProvider>,
      )

    it('the header affordances raise "coming soon" toasts', () => {
      renderWithToast()
      fireEvent.click(screen.getByTestId('scrub-add-pattern'))
      expect(screen.getByText('Add-pattern editor is coming soon')).toBeInTheDocument()
      fireEvent.click(screen.getByTestId('scrub-export-config'))
      expect(screen.getByText('Config export is coming soon')).toBeInTheDocument()
    })

    it('the detail edit / test affordances raise per-pattern toasts', () => {
      renderWithToast()
      // OPENAI_KEY is the default selection.
      fireEvent.click(screen.getByTestId('scrub-detail-edit'))
      expect(
        screen.getByText('Regex editor for OPENAI_KEY is coming soon'),
      ).toBeInTheDocument()
      fireEvent.click(screen.getByTestId('scrub-detail-test'))
      expect(
        screen.getByText('Tested OPENAI_KEY against the last 24h of traffic'),
      ).toBeInTheDocument()
    })

    it('disabling then re-enabling the selected pattern toasts both directions', () => {
      renderWithToast()
      // First click: OPENAI_KEY is enabled -> "disabled" (error variant).
      fireEvent.click(screen.getByTestId('scrub-detail-disable'))
      const disabledToast = screen.getByText('OPENAI_KEY disabled')
      expect(disabledToast).toBeInTheDocument()
      expect(disabledToast.closest('[data-testid="toast"]')).toHaveAttribute(
        'data-variant',
        'error',
      )
      expect(screen.getByTestId('scrub-stats-enabled-count')).toHaveTextContent(
        `${ENABLED - 1}/${TOTAL} patterns enabled`,
      )

      // Second click: now disabled -> "enabled" (success variant).
      fireEvent.click(screen.getByTestId('scrub-detail-disable'))
      const enabledToast = screen.getByText('OPENAI_KEY enabled')
      expect(enabledToast).toBeInTheDocument()
      expect(enabledToast.closest('[data-testid="toast"]')).toHaveAttribute(
        'data-variant',
        'success',
      )
      expect(screen.getByTestId('scrub-stats-enabled-count')).toHaveTextContent(
        `${ENABLED}/${TOTAL} patterns enabled`,
      )
    })
  })
})
