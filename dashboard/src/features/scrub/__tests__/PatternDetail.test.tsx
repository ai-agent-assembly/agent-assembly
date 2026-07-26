import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PatternDetail } from '../PatternDetail'
import { BUILT_IN_DETECTORS } from '../detectors'

const AWS = BUILT_IN_DETECTORS.find((d) => d.id === 'AwsAccessKey')!
const ENTROPY = BUILT_IN_DETECTORS.find((d) => d.id === 'GenericHighEntropy')!

const renderDetail = (
  overrides: Partial<React.ComponentProps<typeof PatternDetail>> = {},
) =>
  render(
    <PatternDetail
      detector={AWS}
      collapsed={false}
      onToggleCollapsed={vi.fn()}
      {...overrides}
    />,
  )

describe('PatternDetail', () => {
  it('states how the kind is really detected, and its category', () => {
    renderDetail()
    expect(screen.getByTestId('scrub-detail-detection')).toHaveTextContent('AKIA')
    expect(screen.getByTestId('scrub-detail-cat')).toHaveTextContent('api-key')
  })

  it('shows the redaction label the gateway actually emits', () => {
    renderDetail()
    expect(screen.getByTestId('scrub-detail-replace')).toHaveTextContent(
      '[REDACTED:AwsAccessKey]',
    )
  })

  it('labels the browser regex as an approximation, not as the detector', () => {
    renderDetail()
    const value = screen.getByTestId('scrub-detail-preview-regex')
    expect(value).toHaveAttribute('data-truth-state', 'known')
    expect(screen.getByText('preview approximation')).toBeInTheDocument()
  })

  it('renders an explicit absence where the browser cannot approximate the detector', () => {
    renderDetail({ detector: ENTROPY })
    const value = screen.getByTestId('scrub-detail-preview-regex')
    expect(value).toHaveAttribute('data-truth-state', 'not-supported')
    expect(value).toHaveTextContent('—')
  })

  it('hides the body when collapsed and shows it when expanded', () => {
    const { rerender } = renderDetail({ collapsed: true })
    expect(screen.queryByTestId('scrub-detail-body')).toBeNull()
    rerender(<PatternDetail detector={AWS} collapsed={false} onToggleCollapsed={vi.fn()} />)
    expect(screen.getByTestId('scrub-detail-body')).toBeInTheDocument()
  })

  it('fires onToggleCollapsed when the toggle button is clicked', () => {
    const onToggle = vi.fn()
    renderDetail({ onToggleCollapsed: onToggle })
    fireEvent.click(screen.getByTestId('scrub-detail-collapse'))
    expect(onToggle).toHaveBeenCalledTimes(1)
  })

  it('reflects collapsed state in the data-collapsed attribute', () => {
    renderDetail({ collapsed: true })
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'true')
  })

  it('disables the two actions with no production path, and says why', () => {
    // "test on traffic" reported a result for a test it never ran; "disable"
    // claimed a per-detector switch the gateway does not have (AAASM-5174).
    renderDetail()
    expect(screen.getByTestId('scrub-detail-test')).toBeDisabled()
    expect(screen.getByTestId('scrub-detail-disable')).toBeDisabled()
    expect(screen.getByTestId('scrub-detail-actions-note')).toHaveTextContent('AAASM-5174')
  })

  it('does not fire a callback from a disabled action even if one is clicked', () => {
    const onEditPatterns = vi.fn()
    renderDetail({ onEditPatterns })
    fireEvent.click(screen.getByTestId('scrub-detail-test'))
    fireEvent.click(screen.getByTestId('scrub-detail-disable'))
    expect(onEditPatterns).not.toHaveBeenCalled()
  })

  it('routes the remaining action to policy authoring', () => {
    const onEditPatterns = vi.fn()
    renderDetail({ onEditPatterns })
    fireEvent.click(screen.getByTestId('scrub-detail-edit'))
    expect(onEditPatterns).toHaveBeenCalledTimes(1)
  })

  it('hides the action row when collapsed', () => {
    renderDetail({ collapsed: true })
    expect(screen.queryByTestId('scrub-detail-actions')).toBeNull()
  })
})
