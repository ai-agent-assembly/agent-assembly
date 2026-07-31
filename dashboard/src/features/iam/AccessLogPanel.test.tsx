/**
 * Render-level guard for AAASM-5111.
 *
 * The panel used to render ten fabricated security events — successful *and*
 * failed logins, attributed to named identities from invented source IPs — in
 * a filterable, paginated table with no disclaimer. The assertions below are
 * written against what an operator would actually see during an incident
 * review: no rows, no addresses, no verdicts, and an explicit statement that
 * there is no source.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { AccessLogPanel } from './AccessLogPanel'

/** Identities and addresses that only ever existed in the deleted seed. */
const FABRICATED_IDENTITIES = [
  'alice@agent-assembly.dev',
  'bob@agent-assembly.dev',
  'carol@agent-assembly.dev',
  'gateway-ci',
  'observability-exporter',
  'retired-runner',
]
const FABRICATED_IPS = ['10.0.0.42', '10.0.0.99', '10.0.0.7', '10.0.0.51', '10.0.0.8', '10.0.0.250']

/** Anything IPv4-shaped, so a *new* invented address fails this too. */
const IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

function renderPanel() {
  return render(
    <MemoryRouter>
      <AccessLogPanel />
    </MemoryRouter>,
  )
}

describe('AccessLogPanel — nothing fabricated renders (AAASM-5111)', () => {
  it('renders no event table and no pagination', () => {
    renderPanel()
    expect(screen.getByTestId('iam-panel-access-log')).toBeInTheDocument()
    expect(screen.queryByTestId('access-log-table')).not.toBeInTheDocument()
    expect(screen.queryByTestId('access-log-page-indicator')).not.toBeInTheDocument()
  })

  it('renders none of the seed identities', () => {
    renderPanel()
    const panel = screen.getByTestId('iam-panel-access-log')
    for (const identity of FABRICATED_IDENTITIES) {
      expect(panel).not.toHaveTextContent(identity)
    }
  })

  it('renders none of the seed source addresses', () => {
    renderPanel()
    const panel = screen.getByTestId('iam-panel-access-log')
    for (const ip of FABRICATED_IPS) {
      expect(panel).not.toHaveTextContent(ip)
    }
  })

  it('renders no IP-shaped text at all, so a fresh invention fails too', () => {
    renderPanel()
    expect(screen.getByTestId('iam-panel-access-log').textContent ?? '').not.toMatch(IPV4)
  })

  it('renders no success or failure verdict', () => {
    // A fabricated *failed* login is the most damaging row this tab could show.
    renderPanel()
    const panel = screen.getByTestId('iam-panel-access-log')
    expect(panel.querySelector('[class*="result--failure"]')).toBeNull()
    expect(panel.querySelector('[class*="result--success"]')).toBeNull()
  })
})

describe('AccessLogPanel — the honest render (AAASM-5111)', () => {
  it('states the gap as not-supported', () => {
    renderPanel()
    const state = screen.getByTestId('access-log-unsupported')
    expect(state).toHaveAttribute('data-truth-state', 'not-supported')
    expect(state).toHaveTextContent(/not available/i)
  })

  it('announces the absence to assistive tech rather than showing an empty table', () => {
    renderPanel()
    const state = screen.getByTestId('access-log-unsupported')
    expect(state).toHaveTextContent('Not supported — the backend cannot provide this value.')
  })

  it('names the backend tickets that own the gap', () => {
    renderPanel()
    const state = screen.getByTestId('access-log-unsupported')
    expect(state).toHaveTextContent('AAASM-5176')
    expect(state).toHaveTextContent('AAASM-5177')
  })

  it('does not claim an audit source exists but is merely down', () => {
    renderPanel()
    const panel = screen.getByTestId('iam-panel-access-log')
    expect(panel).not.toHaveTextContent(/failed to load/i)
    expect(panel).not.toHaveTextContent(/no access-log events match/i)
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument()
  })

  it('offers the real governance audit log as the working alternative', () => {
    renderPanel()
    expect(screen.getByTestId('access-log-audit-link')).toHaveAttribute('href', '/audit')
  })
})

describe('AccessLogPanel — the filter has no production path (AAASM-5111)', () => {
  it('keeps the filter bar visible but inert', () => {
    renderPanel()
    const bar = screen.getByTestId('access-log-filter-bar')
    expect(bar).toHaveAttribute('data-disabled', 'true')
    expect(screen.getByTestId('access-log-filter-identity')).toBeDisabled()
    expect(screen.getByTestId('access-log-filter-event-type')).toBeDisabled()
    expect(screen.getByTestId('access-log-filter-time-range')).toBeDisabled()
  })

  it('offers no identity to filter by, since none can be attributed', () => {
    renderPanel()
    const select = screen.getByTestId('access-log-filter-identity') as HTMLSelectElement
    expect(Array.from(select.options).map((o) => o.value)).toEqual([''])
  })

  it('cannot be operated into showing rows', async () => {
    renderPanel()
    // The point is that no path through the UI reaches a row, so "no events
    // matched your filter" can never be inferred from an empty result.
    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-event-type'),
      'login',
    )
    expect(screen.getByTestId('access-log-filter-event-type')).toHaveValue('')
    expect(screen.queryByTestId('access-log-table')).not.toBeInTheDocument()
    expect(screen.getByTestId('access-log-unsupported')).toBeInTheDocument()
  })
})
