import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { EmptyState } from './EmptyState'

describe('EmptyState', () => {
  describe('button suppression when handlers are absent', () => {
    it('renders no buttons and no actions wrapper when neither handler is supplied', () => {
      const { container } = render(<EmptyState page="live" />)
      expect(screen.queryByRole('button')).toBeNull()
      expect(container.querySelector('.state-actions')).toBeNull()
    })

    it('renders only the primary button when only onCta is supplied', () => {
      render(<EmptyState page="live" onCta={() => {}} />)
      const buttons = screen.getAllByRole('button')
      expect(buttons).toHaveLength(1)
      expect(buttons[0].textContent).toMatch(/Generate test traffic/)
    })

    it('renders only the secondary button when only onSecondary is supplied', () => {
      render(<EmptyState page="live" onSecondary={() => {}} />)
      const buttons = screen.getAllByRole('button')
      expect(buttons).toHaveLength(1)
      expect(buttons[0].textContent).toMatch(/View 24h history/)
    })

    it('renders both buttons when both handlers are supplied', () => {
      render(<EmptyState page="live" onCta={() => {}} onSecondary={() => {}} />)
      expect(screen.getAllByRole('button')).toHaveLength(2)
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

    it('exposes a `data-testid` keyed on the page slug', () => {
      const { rerender } = render(<EmptyState page="live" />)
      expect(screen.getByTestId('empty-state-live')).toBeInTheDocument()
      rerender(<EmptyState page="capability" />)
      expect(screen.getByTestId('empty-state-capability')).toBeInTheDocument()
    })
  })
})
