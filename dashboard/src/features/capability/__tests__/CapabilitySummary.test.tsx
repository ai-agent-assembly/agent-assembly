import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { absent, known, type CascadeEvidence, type Certain } from '../../../lib/truthfulness'
import { CapabilitySummary } from '../CapabilitySummary'
import type { CapabilityAgent, Resource } from '../types'

const RESOURCES: Resource[] = [
  { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
  { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
]

/**
 * Two agents whose every cell resolved to `allow` — exactly what `aa-api`
 * projects when no policy document constrains anything (AAASM-5106).
 */
const AGENTS: CapabilityAgent[] = ['a', 'b'].map((id) => ({
  id,
  name: `agent-${id}`,
  framework: 'langgraph',
  // Populated for forward-compatibility with AAASM-5104, which makes `trust`
  // required; `50` satisfies both today's `trust?: number` and that change.
  trust: 50,
  status: 'active',
  lastSeen: '2026-07-26T00:00:00Z',
  caps: {
    filesystem: { read: 'allow', write: 'allow', delete: 'allow', exec: 'na' },
    terminal: { read: 'na', write: 'allow', delete: 'na', exec: 'allow' },
  },
}))

const LOADED: Certain<CascadeEvidence> = known({ documentCount: 1 })
const EMPTY: Certain<CascadeEvidence> = known({ documentCount: 0 })

describe('CapabilitySummary', () => {
  it('reports real counts when a policy cascade backs them', () => {
    render(<CapabilitySummary agents={AGENTS} resources={RESOURCES} verb="write" cascade={LOADED} />)
    expect(screen.getByTestId('cap-summary-allow')).toHaveTextContent('4')
    expect(screen.getByTestId('cap-summary-deny')).toHaveTextContent('0')
  })

  it('renders Unconfigured rather than an allow count on an empty cascade', () => {
    // The headline regression: a grid asserting `allow` for every cell purely
    // because no policy constrained it must not be summarised as a measured
    // permission total.
    render(<CapabilitySummary agents={AGENTS} resources={RESOURCES} verb="write" cascade={EMPTY} />)
    for (const id of ['cap-summary-allow', 'cap-summary-deny']) {
      const stat = screen.getByTestId(id)
      expect(stat).toHaveAttribute('data-truth-state', 'unconfigured')
      expect(stat).toHaveTextContent('—')
      expect(stat).not.toHaveTextContent(/\d/)
    }
  })

  /**
   * AAASM-5187. The tile reported a real `0` for a state
   * `GET /capability/matrix` cannot emit — `decide()` returns only
   * `Allow`/`Deny`, unmodelled verbs are `Na` — so the number measured an
   * impossible quantity. ADR 0026 Decision 2 (Accepted) removes `narrow` from
   * this page's surfaces rather than keeping an aspirational placeholder, so
   * the tile is gone rather than relabelled.
   *
   * Pinned closed on both a loaded and an empty cascade: relabelling it as an
   * absence would have kept it on screen in exactly the empty-cascade case,
   * which is every shipped deployment.
   */
  it.each([
    ['a loaded cascade', LOADED],
    ['an empty cascade', EMPTY],
  ])('reports no narrowed count at all under %s', (_label, cascade) => {
    const { container } = render(
      <CapabilitySummary agents={AGENTS} resources={RESOURCES} verb="write" cascade={cascade} />,
    )
    expect(screen.queryByTestId('cap-summary-narrow')).toBeNull()
    expect(container.textContent).not.toMatch(/narrow/i)
  })

  it('renders Not evaluated for the flag column the backend never populates', () => {
    render(<CapabilitySummary agents={AGENTS} resources={RESOURCES} verb="write" cascade={LOADED} />)
    const flagged = screen.getByTestId('cap-summary-flagged')
    expect(flagged).toHaveAttribute('data-truth-state', 'not-evaluated')
    expect(flagged).toHaveTextContent('Not evaluated')
  })

  it('renders one consistent state across the row while the matrix is pending', () => {
    render(
      <CapabilitySummary
        agents={AGENTS}
        resources={RESOURCES}
        verb="write"
        cascade={absent('unknown', 'Request in flight')}
      />,
    )
    for (const id of ['cap-summary-allow', 'cap-summary-deny', 'cap-summary-flagged']) {
      // No stat may claim a failure while the request is merely in flight.
      expect(screen.getByTestId(id)).toHaveAttribute('data-truth-state', 'unknown')
    }
  })

  it('renders Unavailable when the matrix request failed', () => {
    render(
      <CapabilitySummary
        agents={AGENTS}
        resources={RESOURCES}
        verb="write"
        cascade={absent('unavailable', 'HTTP 503')}
      />,
    )
    const allow = screen.getByTestId('cap-summary-allow')
    expect(allow).toHaveAttribute('data-truth-state', 'unavailable')
    expect(allow).toHaveAttribute('title', 'Unavailable — HTTP 503')
  })
})
