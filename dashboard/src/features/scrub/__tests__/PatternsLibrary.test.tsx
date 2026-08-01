/**
 * The catalogue table's contract after it became API-sourced (AAASM-5347).
 *
 * The rows, their categories and their severities now come off
 * `GET /api/v1/scrub/patterns`, so the fixtures here are *response* rows, not
 * the local detector table. The assertions that matter are the count column's:
 * it must read a fetched tally, must say "alerts" rather than "findings", and
 * must fall back to an explicit absence — never `0` — when the tally is absent.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PatternsLibrary } from '../PatternsLibrary'
import { patternAlertsFromQuery, type PatternCountsResponse } from '../api'
import { toCatalogue } from '../catalogue'
import { absent, known } from '../../../lib/truthfulness'
import type { ScrubPatternRow } from '../api'

const row = (kind: string, category: string, severity: string): ScrubPatternRow => ({
  kind,
  redaction_label: `[REDACTED:${kind}]`,
  category,
  severity,
  builtin: true,
})

const ENTRIES = toCatalogue([
  row('AwsAccessKey', 'api_key', 'critical'),
  row('EmailAddress', 'pii', 'low'),
])

const tally = (rows: readonly { kind: string; hits: number }[]) => {
  const body: PatternCountsResponse = {
    counts: [...rows],
    total_hits: rows.reduce((s, r) => s + r.hits, 0),
    window_seconds: 86_400,
  }
  return patternAlertsFromQuery({ data: body })
}

const renderLibrary = (
  overrides: Partial<React.ComponentProps<typeof PatternsLibrary>> = {},
) =>
  render(
    <PatternsLibrary
      entries={ENTRIES}
      alerts={tally([{ kind: 'AwsAccessKey', hits: 4 }])}
      alertWindow={known('24h')}
      selectedKind="AwsAccessKey"
      onSelect={vi.fn()}
      matchCounts={{}}
      {...overrides}
    />,
  )

describe('PatternsLibrary — rows served by the API', () => {
  it('renders one row per served detector, with the category the API sent', () => {
    renderLibrary()
    expect(screen.getByTestId('scrub-patterns-row-AwsAccessKey')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-patterns-row-EmailAddress')).toBeInTheDocument()
    // Verbatim: the API spells it `api_key`, and only the CSS class is slugged.
    expect(screen.getByTestId('scrub-patterns-cat-AwsAccessKey')).toHaveTextContent('api_key')
  })

  it('renders the severity the API serves, not a locally invented ranking', () => {
    // AAASM-5156 removed this column because nothing behind the product modelled
    // severity. `CredentialKind::severity()` does now, and it is served.
    renderLibrary()
    expect(screen.getByTestId('scrub-patterns-sev-AwsAccessKey')).toHaveTextContent('critical')
    expect(screen.getByTestId('scrub-patterns-sev-EmailAddress')).toHaveTextContent('low')
  })

  it('offers no enable/disable control at all', () => {
    renderLibrary()
    // The toggle asserted a per-detector switch the product does not have; its
    // absence is the fix, so its return must fail this test.
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
    expect(screen.queryByTestId('scrub-patterns-toggle-AwsAccessKey')).toBeNull()
  })
})

describe('PatternsLibrary — the count column', () => {
  it('renders the fetched alert count for a kind that fired', () => {
    renderLibrary()
    const cell = screen.getByTestId('scrub-patterns-hits-AwsAccessKey')
    expect(cell).toHaveAttribute('data-truth-state', 'known')
    expect(cell).toHaveTextContent('4')
  })

  it('renders zero for a kind a populated tally omits', () => {
    // The handler emits a row only for kinds that fired, so a kind missing from
    // a populated tally genuinely contributed no alert — a measurement, not a
    // default.
    renderLibrary()
    const cell = screen.getByTestId('scrub-patterns-hits-EmailAddress')
    expect(cell).toHaveAttribute('data-truth-state', 'known')
    expect(cell).toHaveTextContent('0')
  })

  it('renders an explicit absence, never zero, when the tally is unavailable', () => {
    renderLibrary({ alerts: absent('unavailable', 'HTTP 503') })
    for (const kind of ['AwsAccessKey', 'EmailAddress']) {
      const cell = screen.getByTestId(`scrub-patterns-hits-${kind}`)
      expect(cell).toHaveAttribute('data-truth-state', 'unavailable')
      expect(cell.querySelector('.truth-absent__glyph')?.textContent).toBe('—')
      // `\b0\b` rather than a substring check: the reason text legitimately
      // contains "503", and a substring match would pass for the wrong reason.
      expect(cell.textContent ?? '').not.toMatch(/\b0\b/)
    }
  })

  it('renders an explicit absence when the window came back empty', () => {
    // An empty window is also what a caller confined to no team receives, so it
    // must not read as "no credential leaked in the last 24 hours".
    renderLibrary({ alerts: tally([]) })
    const cell = screen.getByTestId('scrub-patterns-hits-AwsAccessKey')
    expect(cell).toHaveAttribute('data-truth-state', 'unknown')
    expect(cell.textContent ?? '').not.toMatch(/\b0\b/)
  })

  it('labels the column alerts — never findings or hits — and states the first-kind rule', () => {
    // The endpoint counts one alert per intercepted action under that alert's
    // first detected kind. Calling that a finding count would overstate the
    // primary kind and silently zero every co-occurring one.
    renderLibrary()
    const header = screen.getByRole('columnheader', { name: /alert/i })
    expect(header).toHaveTextContent('alerts')
    const note = screen.getByTestId('scrub-patterns-alerts-note')
    expect(note).toHaveTextContent(/not\s+findings/i)
    expect(note).toHaveTextContent(/first credential kind/i)
    expect(screen.queryByRole('columnheader', { name: /finding/i })).toBeNull()
  })

  it('totals the column under the column, from the server’s total_hits', () => {
    renderLibrary({ alerts: tally([{ kind: 'AwsAccessKey', hits: 4 }, { kind: 'EmailAddress', hits: 2 }]) })
    const total = screen.getByTestId('scrub-patterns-total')
    expect(screen.getByTestId('scrub-patterns-total-value')).toHaveTextContent('6')
    expect(screen.getByTestId('scrub-patterns-total-kinds')).toHaveTextContent('2')
    expect(total).toHaveTextContent(/alerts across/)
  })

  it('renders the total as an absence, never zero, when the tally is absent', () => {
    renderLibrary({ alerts: absent('unavailable', 'HTTP 503') })
    const value = screen.getByTestId('scrub-patterns-total-value')
    expect(value).toHaveAttribute('data-truth-state', 'unavailable')
    expect(value.textContent ?? '').not.toMatch(/\b0\b/)
  })

  it('states the window the server aggregated over', () => {
    renderLibrary()
    expect(screen.getByTestId('scrub-patterns-window')).toHaveTextContent('24h')
  })

  it('renders the window as an absence when no response established one', () => {
    renderLibrary({ alertWindow: absent('unavailable', 'HTTP 503') })
    expect(screen.getByTestId('scrub-patterns-window')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
  })
})

describe('PatternsLibrary — interaction', () => {
  it('says in visible text that the catalogue is read-only and API-served', () => {
    renderLibrary()
    expect(screen.getByTestId('scrub-patterns-note')).toHaveTextContent(/read-only/i)
    expect(screen.getByTestId('scrub-patterns-note')).toHaveTextContent(
      '/api/v1/scrub/patterns',
    )
  })

  it('shows the in-sample chip only for detectors with non-zero match counts', () => {
    renderLibrary({ matchCounts: { AwsAccessKey: 3 } })
    expect(screen.getByTestId('scrub-patterns-matchchip-AwsAccessKey')).toHaveTextContent(
      '3 in sample',
    )
    expect(screen.queryByTestId('scrub-patterns-matchchip-EmailAddress')).toBeNull()
  })

  it('calls onSelect with the kind when a row is clicked', () => {
    const onSelect = vi.fn()
    renderLibrary({ onSelect })
    fireEvent.click(screen.getByTestId('scrub-patterns-row-EmailAddress'))
    expect(onSelect).toHaveBeenCalledWith('EmailAddress')
  })

  it('filters by name and kind when the search input is non-empty', () => {
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
