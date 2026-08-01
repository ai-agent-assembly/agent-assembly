/**
 * The detail panel's contract after it became API-sourced (AAASM-5347).
 *
 * Its subject is a served catalogue row joined to local preview metadata, so
 * these cover both halves: the four fields the response owns, and the two the
 * dashboard contributes — including the case where it has no transcription for a
 * kind the gateway ships, which must render as an absence, not a blank.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PatternDetail } from '../PatternDetail'
import type { ScrubPatternRow } from '../api'
import { toCatalogue } from '../catalogue'
import { absent, known } from '../../../lib/truthfulness'

const row = (kind: string, category = 'api_key', severity = 'critical'): ScrubPatternRow => ({
  kind,
  redaction_label: `[REDACTED:${kind}]`,
  category,
  severity,
  builtin: true,
})

const [AWS] = toCatalogue([row('AwsAccessKey')])
const [ENTROPY] = toCatalogue([row('GenericHighEntropy', 'generic', 'medium')])
const [UNKNOWN_KIND] = toCatalogue([row('AKindTheDashboardHasNeverHeardOf', 'generic', 'low')])

const renderDetail = (
  overrides: Partial<React.ComponentProps<typeof PatternDetail>> = {},
) =>
  render(
    <PatternDetail
      entry={AWS}
      alerts={known(4)}
      alertWindow={known('24h')}
      collapsed={false}
      onToggleCollapsed={vi.fn()}
      {...overrides}
    />,
  )

describe('PatternDetail — fields the response owns', () => {
  it('shows the category and severity the API served', () => {
    renderDetail()
    expect(screen.getByTestId('scrub-detail-cat')).toHaveTextContent('api_key')
    expect(screen.getByTestId('scrub-detail-sev')).toHaveTextContent('critical')
  })

  it('shows the redaction label from the response rather than rebuilding it', () => {
    // Rebuilding it locally is how the panel once taught `[REDACTED:PEM]`, a
    // label `aa-security` never writes (ADR 0015).
    renderDetail()
    expect(screen.getByTestId('scrub-detail-replace')).toHaveTextContent(
      '[REDACTED:AwsAccessKey]',
    )
  })
})

describe('PatternDetail — fields the dashboard contributes', () => {
  it('states how the kind is really detected', () => {
    renderDetail()
    expect(screen.getByTestId('scrub-detail-detection')).toHaveTextContent('AKIA')
  })

  it('labels the browser regex as an approximation, not as the detector', () => {
    renderDetail()
    const value = screen.getByTestId('scrub-detail-preview-regex')
    expect(value).toHaveAttribute('data-truth-state', 'known')
    expect(screen.getByText('preview approximation')).toBeInTheDocument()
  })

  it('renders an explicit absence where the browser cannot approximate the detector', () => {
    renderDetail({ entry: ENTROPY })
    const value = screen.getByTestId('scrub-detail-preview-regex')
    expect(value).toHaveAttribute('data-truth-state', 'not-supported')
    expect(value).toHaveTextContent('—')
  })

  it('renders the detection prose as unknown for a served kind it cannot describe', () => {
    // The gateway may ship a `CredentialKind` this dashboard build predates.
    // `unknown`, not `not-supported`: the answer exists, this build lacks it.
    renderDetail({ entry: UNKNOWN_KIND })
    const value = screen.getByTestId('scrub-detail-detection-value')
    expect(value).toHaveAttribute('data-truth-state', 'unknown')
    expect(screen.getByTestId('scrub-detail')).toHaveTextContent('AKindTheDashboardHasNeverHeardOf')
  })
})

describe('PatternDetail — the alert count', () => {
  it('shows the count for this kind and the window it covers', () => {
    renderDetail()
    expect(screen.getByTestId('scrub-detail-alerts-value')).toHaveTextContent('4')
    expect(screen.getByTestId('scrub-detail-window')).toHaveTextContent('24h')
  })

  it('states inline that the figure counts alerts, not findings', () => {
    // A tooltip is not reachable by every operator, and this distinction is the
    // difference between a count and an overstatement.
    renderDetail()
    expect(screen.getByTestId('scrub-detail-alerts-hint')).toHaveTextContent(/not findings/i)
    expect(screen.getByTestId('scrub-detail-alerts-hint')).toHaveTextContent(/first credential kind/i)
  })

  it('renders an explicit absence, never zero, when the tally failed', () => {
    renderDetail({ alerts: absent('unavailable', 'HTTP 503') })
    const value = screen.getByTestId('scrub-detail-alerts-value')
    expect(value).toHaveAttribute('data-truth-state', 'unavailable')
    expect(value.querySelector('.truth-absent__glyph')?.textContent).toBe('—')
    // `\b0\b` rather than a substring check: the reason text contains "503".
    expect(value.textContent ?? '').not.toMatch(/\b0\b/)
  })
})

describe('PatternDetail — collapse and actions', () => {
  it('hides the body when collapsed and shows it when expanded', () => {
    const { rerender } = renderDetail({ collapsed: true })
    expect(screen.queryByTestId('scrub-detail-body')).toBeNull()
    rerender(
      <PatternDetail
        entry={AWS}
        alerts={known(4)}
        alertWindow={known('24h')}
        collapsed={false}
        onToggleCollapsed={vi.fn()}
      />,
    )
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
    // claimed a per-detector switch the gateway does not have. None of the three
    // routes AAASM-5174 shipped changed either fact.
    renderDetail()
    expect(screen.getByTestId('scrub-detail-test')).toBeDisabled()
    expect(screen.getByTestId('scrub-detail-disable')).toBeDisabled()
    expect(screen.getByTestId('scrub-detail-actions-note')).toHaveTextContent(/no API behind them/i)
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
