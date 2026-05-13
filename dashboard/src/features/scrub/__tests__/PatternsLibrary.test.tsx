import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PatternsLibrary } from '../PatternsLibrary'
import type { ScrubPattern } from '../types'

const PATTERNS: ScrubPattern[] = [
  {
    id: 'AWS_KEY',
    name: 'AWS access key',
    regex: 'AKIA[0-9A-Z]{16}',
    example: 'AKIAIOSFODNN7EXAMPLE',
    replace: '[REDACTED:AWS_KEY]',
    severity: 'critical',
    hits24h: 14,
    enabled: true,
  },
  {
    id: 'PHONE',
    name: 'Phone',
    regex: '[0-9]{10}',
    example: '0123456789',
    replace: '[REDACTED:PHONE]',
    severity: 'low',
    hits24h: 12,
    enabled: false,
  },
  {
    id: 'EMAIL_PII',
    name: 'Email',
    regex: '[a-z]+@[a-z]+',
    example: 'a@b',
    replace: '[REDACTED:EMAIL]',
    severity: 'medium',
    hits24h: 87,
    enabled: true,
  },
]

describe('PatternsLibrary', () => {
  it('renders one row per pattern with severity, hits, and a toggle', () => {
    render(
      <PatternsLibrary
        patterns={PATTERNS}
        selectedId="AWS_KEY"
        onSelect={vi.fn()}
        onToggle={vi.fn()}
        matchCounts={{}}
      />,
    )
    expect(screen.getByTestId('scrub-patterns-row-AWS_KEY')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-patterns-row-PHONE')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-patterns-row-EMAIL_PII')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-patterns-sev-AWS_KEY')).toHaveTextContent('critical')
  })

  it('shows the in-sample chip only for patterns with non-zero match counts', () => {
    render(
      <PatternsLibrary
        patterns={PATTERNS}
        selectedId="AWS_KEY"
        onSelect={vi.fn()}
        onToggle={vi.fn()}
        matchCounts={{ AWS_KEY: 3 }}
      />,
    )
    expect(screen.getByTestId('scrub-patterns-matchchip-AWS_KEY')).toHaveTextContent(
      '3 in sample',
    )
    expect(screen.queryByTestId('scrub-patterns-matchchip-EMAIL_PII')).toBeNull()
  })

  it('calls onSelect when a row is clicked', () => {
    const onSelect = vi.fn()
    render(
      <PatternsLibrary
        patterns={PATTERNS}
        selectedId="AWS_KEY"
        onSelect={onSelect}
        onToggle={vi.fn()}
        matchCounts={{}}
      />,
    )
    fireEvent.click(screen.getByTestId('scrub-patterns-row-EMAIL_PII'))
    expect(onSelect).toHaveBeenCalledWith('EMAIL_PII')
  })

  it('calls onToggle (and not onSelect) when the checkbox is clicked', () => {
    const onSelect = vi.fn()
    const onToggle = vi.fn()
    render(
      <PatternsLibrary
        patterns={PATTERNS}
        selectedId="AWS_KEY"
        onSelect={onSelect}
        onToggle={onToggle}
        matchCounts={{}}
      />,
    )
    fireEvent.click(screen.getByTestId('scrub-patterns-toggle-EMAIL_PII'))
    expect(onToggle).toHaveBeenCalledWith('EMAIL_PII')
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('filters by name and id when the search input is non-empty', () => {
    render(
      <PatternsLibrary
        patterns={PATTERNS}
        selectedId="AWS_KEY"
        onSelect={vi.fn()}
        onToggle={vi.fn()}
        matchCounts={{}}
      />,
    )
    const search = screen.getByTestId('scrub-patterns-search')
    fireEvent.change(search, { target: { value: 'phone' } })
    expect(screen.queryByTestId('scrub-patterns-row-AWS_KEY')).toBeNull()
    expect(screen.getByTestId('scrub-patterns-row-PHONE')).toBeInTheDocument()
  })

  it('shows the empty-search row when no patterns match', () => {
    render(
      <PatternsLibrary
        patterns={PATTERNS}
        selectedId="AWS_KEY"
        onSelect={vi.fn()}
        onToggle={vi.fn()}
        matchCounts={{}}
      />,
    )
    fireEvent.change(screen.getByTestId('scrub-patterns-search'), {
      target: { value: 'xyznomatch' },
    })
    expect(screen.getByTestId('scrub-patterns-empty')).toBeInTheDocument()
  })
})
