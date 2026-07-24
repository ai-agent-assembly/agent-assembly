import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ErrorState } from './ErrorState'

describe('ErrorState', () => {
  describe('live runtime-disconnected banner', () => {
    it('renders the P1 banner above the block for kind="live"', () => {
      // Regression for AAASM-5062: the live variant must surface the
      // full-width RUNTIME DISCONNECTED banner from the hi-fi spec.
      render(<ErrorState kind="live" />)
      const banner = screen.getByTestId('runtime-down-banner')
      expect(banner).toBeInTheDocument()
      expect(banner.textContent).toMatch(/RUNTIME DISCONNECTED/)
      expect(banner.textContent).toMatch(/last heartbeat/)
      expect(banner.textContent).toMatch(/auto-retry/)
      expect(banner.textContent).toMatch(/severity: P1/)
      expect(banner.querySelector('.pulse')).not.toBeNull()
    })

    it('does not render the banner for the generic variant', () => {
      render(<ErrorState kind="generic" />)
      expect(screen.queryByTestId('runtime-down-banner')).toBeNull()
    })
  })

  describe('actions', () => {
    it('renders the retry and secondary buttons', () => {
      render(<ErrorState kind="generic" />)
      expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Open status page/ })).toBeInTheDocument()
    })
  })
})
