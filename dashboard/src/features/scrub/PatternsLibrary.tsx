/**
 * The shipped detector catalogue, rendered read-only (AAASM-5156 / AAASM-5174).
 *
 * Two claims were removed from this table and neither is replaced by a
 * substitute value:
 *
 *  - **the per-row enable/disable checkbox.** It flipped a boolean in local
 *    React state; nothing was persisted or transmitted, so the page *confirmed*
 *    a change it had not made. It also toggled a concept the product does not
 *    model — `ScannerConfig` offers a global kill switch and additive custom
 *    patterns, not a per-detector switch. Whether it should is ADR 0026
 *    Decision 3 (`Proposed`); this component neither builds nor forecloses that,
 *    it just stops asserting a state it cannot know. The column now states the
 *    one thing that *is* checkable — where the detector comes from.
 *  - **the 24h hit count.** No endpoint aggregates by detector kind, so the
 *    column renders the shared absence marker instead of a fixture integer.
 *
 * The in-sample chip stays: it counts matches in the payload the operator typed
 * into this page, which is a local fact about local input, not a claim about
 * production traffic.
 */
import { useMemo, useState } from 'react'
import { TruthfulValue } from '../../components/truthfulness'
import { DETECTOR_HITS_24H } from './posture'
import type { ScrubDetector } from './types'
import './PatternsLibrary.css'

export interface PatternsLibraryProps {
  detectors: readonly ScrubDetector[]
  selectedId: string
  onSelect: (id: string) => void
  matchCounts: Record<string, number>
}

export function PatternsLibrary({
  detectors,
  selectedId,
  onSelect,
  matchCounts,
}: Readonly<PatternsLibraryProps>) {
  const [search, setSearch] = useState('')
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return detectors
    return detectors.filter(
      (d) => d.name.toLowerCase().includes(q) || d.id.toLowerCase().includes(q),
    )
  }, [detectors, search])

  return (
    <section
      className="scrub-patterns"
      aria-label="detector catalogue"
      data-testid="scrub-patterns"
    >
      <header className="scrub-patterns-head">
        <h3 className="scrub-patterns-title">▤ detector catalogue</h3>
        <input
          type="search"
          className="scrub-patterns-search"
          placeholder="search…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="search detectors"
          data-testid="scrub-patterns-search"
        />
      </header>
      <p className="scrub-patterns-note" data-testid="scrub-patterns-note">
        Read-only. These detectors are compiled into the gateway scanner; the API
        exposes no way to switch one on or off, so this is a catalogue, not a
        control panel (AAASM-5174).
      </p>
      <div className="scrub-patterns-table-wrap">
        <table className="scrub-patterns-table">
          <thead>
            <tr>
              <th scope="col" className="scrub-patterns-col-origin">
                origin
              </th>
              <th scope="col">detector</th>
              <th scope="col">category</th>
              <th scope="col" className="scrub-patterns-col-hits">
                24h
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={4}
                  className="scrub-patterns-empty"
                  data-testid="scrub-patterns-empty"
                >
                  no detectors match &ldquo;{search}&rdquo;
                </td>
              </tr>
            ) : (
              filtered.map((d) => {
                const active = d.id === selectedId
                const matchN = matchCounts[d.id] ?? 0
                return (
                  <tr
                    key={d.id}
                    className={`scrub-patterns-row${active ? ' is-active' : ''}`}
                    onClick={() => onSelect(d.id)}
                    data-testid={`scrub-patterns-row-${d.id}`}
                  >
                    <td className="scrub-patterns-origin-cell">
                      <span
                        className={`scrub-patterns-origin scrub-patterns-origin--${d.origin}`}
                        data-testid={`scrub-patterns-origin-${d.id}`}
                      >
                        {d.origin === 'built-in' ? 'built-in' : 'policy'}
                      </span>
                    </td>
                    <td>
                      <div className="scrub-patterns-name">
                        {d.name}
                        {matchN > 0 && (
                          <span
                            className="scrub-patterns-chip"
                            data-testid={`scrub-patterns-matchchip-${d.id}`}
                          >
                            {matchN} in sample
                          </span>
                        )}
                      </div>
                      <div className="scrub-patterns-id">{d.id}</div>
                    </td>
                    <td>
                      <span
                        className={`scrub-patterns-cat scrub-patterns-cat--${d.category}`}
                        data-testid={`scrub-patterns-cat-${d.id}`}
                      >
                        {d.category}
                      </span>
                    </td>
                    <td className="scrub-patterns-hits">
                      <TruthfulValue
                        value={DETECTOR_HITS_24H}
                        testId={`scrub-patterns-hits-${d.id}`}
                      />
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
