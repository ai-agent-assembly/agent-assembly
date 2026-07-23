import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { VerdictChip } from './VerdictChip'
import type { Verdict } from '../../features/trace/decision'

const ALL: Array<[Verdict, string]> = [
  ['allowed', 'ALLOWED'],
  ['narrowed', 'NARROWED'],
  ['scrubbed', 'SCRUBBED'],
  ['pending', 'PENDING'],
  ['denied', 'DENIED'],
]

describe('VerdictChip', () => {
  it.each(ALL)('renders the full label and data-verdict for %s', (verdict, label) => {
    render(<VerdictChip verdict={verdict} />)
    const chip = screen.getByTestId('verdict-chip')
    expect(chip).toHaveAttribute('data-verdict', verdict)
    expect(chip).toHaveTextContent(label)
  })

  it('renders the glyph only in compact mode but keeps the full label as the title', () => {
    render(<VerdictChip verdict="denied" variant="compact" />)
    const chip = screen.getByTestId('verdict-chip')
    expect(chip).toHaveTextContent('✕')
    expect(chip).not.toHaveTextContent('DENIED')
    expect(chip).toHaveAttribute('title', '✕ DENIED')
  })

  it('supports all five verdicts of the decision vocabulary', () => {
    // Guards against dropping a verdict from VERDICT_META.
    expect(ALL).toHaveLength(5)
  })
})
