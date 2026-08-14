import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { EmptyState } from './EmptyState'

describe('EmptyState', () => {
  describe('buttons render from copy, not handler presence', () => {
    it('renders both copy-defined buttons even when no handlers are supplied', () => {
      // Regression for AAASM-5061: pages that render EmptyState without
      // passing handlers must still show the CTAs the copy defines.
      render(<EmptyState page="live" />)
      const buttons = screen.getAllByRole('button')
      expect(buttons).toHaveLength(2)
      expect(buttons[0].textContent).toMatch(/Generate test traffic/)
      expect(buttons[1].textContent).toMatch(/View 24h history/)
    })

    it('renders both copy-defined buttons regardless of which handler is supplied', () => {
      render(<EmptyState page="live" onCta={() => {}} />)
      expect(screen.getAllByRole('button')).toHaveLength(2)
    })

    it('clicking a copy-defined button with no handler does not throw', async () => {
      const user = userEvent.setup()
      render(<EmptyState page="live" />)
      await user.click(screen.getByRole('button', { name: /Generate test traffic/ }))
      expect(screen.getByRole('button', { name: /Generate test traffic/ })).toBeInTheDocument()
    })

    it('renders only the primary button when copy defines no secondary', () => {
      // The `fleet` COPY entry has a cta but secondary: null.
      const { container } = render(<EmptyState page="fleet" />)
      const buttons = screen.getAllByRole('button')
      expect(buttons).toHaveLength(1)
      expect(buttons[0].textContent).toMatch(/Clear filters/)
      expect(container.querySelector('.state-actions')).not.toBeNull()
    })
  })

  describe('button click wiring', () => {
    it('clicking the primary button calls onCta', async () => {
      const user = userEvent.setup()
      const onCta = vi.fn()
      render(<EmptyState page="live" onCta={onCta} />)
      await user.click(screen.getByRole('button', { name: /Generate test traffic/ }))
      expect(onCta).toHaveBeenCalledTimes(1)
    })

    it('clicking the secondary button calls onSecondary', async () => {
      const user = userEvent.setup()
      const onSecondary = vi.fn()
      render(<EmptyState page="live" onSecondary={onSecondary} />)
      await user.click(screen.getByRole('button', { name: /View 24h history/ }))
      expect(onSecondary).toHaveBeenCalledTimes(1)
    })
  })

  describe('variants with null CTA in COPY', () => {
    it('approvals variant never renders buttons regardless of handlers', () => {
      // The `approvals` COPY entry has cta: null + secondary: null.
      // Supplying handlers must not conjure buttons that don't exist in copy.
      render(
        <EmptyState page="approvals" onCta={() => {}} onSecondary={() => {}} />,
      )
      expect(screen.queryByRole('button')).toBeNull()
    })

    it('scrub variant never renders buttons regardless of handlers', () => {
      render(<EmptyState page="scrub" onCta={() => {}} onSecondary={() => {}} />)
      expect(screen.queryByRole('button')).toBeNull()
    })
  })

  describe('content rendering', () => {
    it('renders the canned icon / tag / title / message for the live variant', () => {
      render(<EmptyState page="live" />)
      expect(screen.getByText(/No traffic in the last 60s/)).toBeInTheDocument()
      expect(screen.getByText(/runtime · idle/)).toBeInTheDocument()
    })

    it('keeps the restored trailing copy from the hi-fi spec', () => {
      // Regression for AAASM-5062: these sentences were trimmed and restored.
      const { rerender } = render(<EmptyState page="fleet" />)
      expect(screen.getByText(/last\s+fleet sync/)).toBeInTheDocument()
      rerender(<EmptyState page="capability" />)
      expect(screen.getByText(/to populate\s+this view/)).toBeInTheDocument()
      rerender(<EmptyState page="agent" />)
      expect(screen.getByText(/AGENT_ASSEMBLY_TOKEN/)).toBeInTheDocument()
      rerender(<EmptyState page="scrub" />)
      expect(screen.getByText(/scan\s+and replace matches in real time/)).toBeInTheDocument()
    })

    it('exposes a `data-testid` keyed on the page slug', () => {
      const { rerender } = render(<EmptyState page="live" />)
      expect(screen.getByTestId('empty-state-live')).toBeInTheDocument()
      rerender(<EmptyState page="capability" />)
      expect(screen.getByTestId('empty-state-capability')).toBeInTheDocument()
    })
  })
})
