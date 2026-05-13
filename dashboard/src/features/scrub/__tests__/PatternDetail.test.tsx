import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PatternDetail } from '../PatternDetail'
import type { ScrubPattern } from '../types'

const SAMPLE: ScrubPattern = {
  id: 'AWS_KEY',
  name: 'AWS access key ID',
  regex: 'AKIA[0-9A-Z]{16}',
  example: 'AKIAIOSFODNN7EXAMPLE',
  replace: '[REDACTED:AWS_KEY]',
  severity: 'critical',
  hits24h: 14,
  enabled: true,
}

describe('PatternDetail', () => {
  it('renders the regex / example / replace cells when not collapsed', () => {
    render(
      <PatternDetail
        pattern={SAMPLE}
        collapsed={false}
        onToggleCollapsed={vi.fn()}
      />,
    )
    expect(screen.getByTestId('scrub-detail-regex')).toHaveTextContent(SAMPLE.regex)
    expect(screen.getByTestId('scrub-detail-example')).toHaveTextContent(SAMPLE.example)
    expect(screen.getByTestId('scrub-detail-replace')).toHaveTextContent(SAMPLE.replace)
    expect(screen.getByTestId('scrub-detail-sev')).toHaveTextContent('critical')
  })

  it('hides the body when collapsed and shows it when expanded', () => {
    const { rerender } = render(
      <PatternDetail
        pattern={SAMPLE}
        collapsed={true}
        onToggleCollapsed={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('scrub-detail-body')).toBeNull()
    rerender(
      <PatternDetail
        pattern={SAMPLE}
        collapsed={false}
        onToggleCollapsed={vi.fn()}
      />,
    )
    expect(screen.getByTestId('scrub-detail-body')).toBeInTheDocument()
  })

  it('fires onToggleCollapsed when the toggle button is clicked', () => {
    const onToggle = vi.fn()
    render(
      <PatternDetail
        pattern={SAMPLE}
        collapsed={false}
        onToggleCollapsed={onToggle}
      />,
    )
    fireEvent.click(screen.getByTestId('scrub-detail-collapse'))
    expect(onToggle).toHaveBeenCalledTimes(1)
  })

  it('reflects collapsed state in the data-collapsed attribute', () => {
    render(
      <PatternDetail
        pattern={SAMPLE}
        collapsed={true}
        onToggleCollapsed={vi.fn()}
      />,
    )
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'true')
  })
})
