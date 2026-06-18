import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ScrubPage } from './ScrubPage'
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
})
