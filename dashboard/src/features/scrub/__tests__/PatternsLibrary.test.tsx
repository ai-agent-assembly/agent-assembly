import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PatternsLibrary } from '../PatternsLibrary'
import { BUILT_IN_DETECTORS } from '../detectors'
import type { ScrubDetector } from '../types'

const DETECTORS: ScrubDetector[] = [
  BUILT_IN_DETECTORS.find((d) => d.id === 'AwsAccessKey')!,
  BUILT_IN_DETECTORS.find((d) => d.id === 'EmailAddress')!,
  BUILT_IN_DETECTORS.find((d) => d.id === 'Custom')!,
]

const renderLibrary = (
  overrides: Partial<React.ComponentProps<typeof PatternsLibrary>> = {},
) =>
  render(
    <PatternsLibrary
      detectors={DETECTORS}
      selectedId="AwsAccessKey"
      onSelect={vi.fn()}
      matchCounts={{}}
      {...overrides}
    />,
  )

describe('PatternsLibrary', () => {
  it('renders one row per detector with its category and origin', () => {
    renderLibrary()
    expect(screen.getByTestId('scrub-patterns-row-AwsAccessKey')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-patterns-row-EmailAddress')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-patterns-cat-AwsAccessKey')).toHaveTextContent('api-key')
    expect(screen.getByTestId('scrub-patterns-origin-AwsAccessKey')).toHaveTextContent('built-in')
    expect(screen.getByTestId('scrub-patterns-origin-Custom')).toHaveTextContent('policy')
  })

  it('offers no enable/disable control at all', () => {
    renderLibrary()
    // The toggle asserted a per-detector switch the product does not have; its
    // absence is the fix, so its return must fail this test (AAASM-5174).
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
    expect(screen.queryByTestId('scrub-patterns-toggle-AwsAccessKey')).toBeNull()
  })

  it('renders every 24h cell as an explicit absence, never a number', () => {
    renderLibrary()
    for (const d of DETECTORS) {
      const cell = screen.getByTestId(`scrub-patterns-hits-${d.id}`)
      expect(cell).toHaveAttribute('data-truth-state', 'not-supported')
      // The visible cell is the glyph alone: no count of any kind survives.
      expect(cell.querySelector('.truth-absent__glyph')?.textContent).toBe('—')
    }
  })

  it('says in visible text that the catalogue is read-only', () => {
    renderLibrary()
    expect(screen.getByTestId('scrub-patterns-note')).toHaveTextContent(/read-only/i)
    expect(screen.getByTestId('scrub-patterns-note')).toHaveTextContent('AAASM-5174')
  })

  it('shows the in-sample chip only for detectors with non-zero match counts', () => {
    renderLibrary({ matchCounts: { AwsAccessKey: 3 } })
    expect(screen.getByTestId('scrub-patterns-matchchip-AwsAccessKey')).toHaveTextContent(
      '3 in sample',
    )
    expect(screen.queryByTestId('scrub-patterns-matchchip-EmailAddress')).toBeNull()
  })

  it('calls onSelect when a row is clicked', () => {
    const onSelect = vi.fn()
    renderLibrary({ onSelect })
    fireEvent.click(screen.getByTestId('scrub-patterns-row-EmailAddress'))
    expect(onSelect).toHaveBeenCalledWith('EmailAddress')
  })

  it('filters by name and id when the search input is non-empty', () => {
    renderLibrary()
    fireEvent.change(screen.getByTestId('scrub-patterns-search'), {
      target: { value: 'email' },
    })
    expect(screen.queryByTestId('scrub-patterns-row-AwsAccessKey')).toBeNull()
    expect(screen.getByTestId('scrub-patterns-row-EmailAddress')).toBeInTheDocument()
  })

  it('shows the empty-search row when no detector matches', () => {
    renderLibrary()
    fireEvent.change(screen.getByTestId('scrub-patterns-search'), {
      target: { value: 'xyznomatch' },
    })
    expect(screen.getByTestId('scrub-patterns-empty')).toBeInTheDocument()
  })
})
