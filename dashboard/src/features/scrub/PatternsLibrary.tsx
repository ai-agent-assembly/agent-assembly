import { useMemo, useState } from 'react'
import type { ScrubPattern } from './types'
import './PatternsLibrary.css'

export interface PatternsLibraryProps {
  patterns: ScrubPattern[]
  selectedId: string
  onSelect: (id: string) => void
  onToggle: (id: string) => void
  matchCounts: Record<string, number>
}

export function PatternsLibrary({
  patterns,
  selectedId,
  onSelect,
  onToggle,
  matchCounts,
}: PatternsLibraryProps) {
  const [search, setSearch] = useState('')
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return patterns
    return patterns.filter(
      (p) => p.name.toLowerCase().includes(q) || p.id.toLowerCase().includes(q),
    )
  }, [patterns, search])

  return (
    <section
      className="scrub-patterns"
      aria-label="patterns library"
      data-testid="scrub-patterns"
    >
      <header className="scrub-patterns-head">
        <h3 className="scrub-patterns-title">▤ patterns library</h3>
        <input
          type="search"
          className="scrub-patterns-search"
          placeholder="search…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="search patterns"
          data-testid="scrub-patterns-search"
        />
      </header>
      <div className="scrub-patterns-table-wrap">
        <table className="scrub-patterns-table">
          <thead>
            <tr>
              <th scope="col" className="scrub-patterns-col-toggle">
                <span className="scrub-sr-only">enabled</span>
              </th>
              <th scope="col">pattern</th>
              <th scope="col">sev</th>
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
                  no patterns match &ldquo;{search}&rdquo;
                </td>
              </tr>
            ) : (
              filtered.map((p) => {
                const active = p.id === selectedId
                const matchN = matchCounts[p.id] ?? 0
                return (
                  <tr
                    key={p.id}
                    className={`scrub-patterns-row${active ? ' is-active' : ''}${
                      p.enabled ? '' : ' is-disabled'
                    }`}
                    onClick={() => onSelect(p.id)}
                    data-testid={`scrub-patterns-row-${p.id}`}
                  >
                    <td
                      className="scrub-patterns-toggle-cell"
                      onClick={(e) => {
                        e.stopPropagation()
                        onToggle(p.id)
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={p.enabled}
                        onChange={() => onToggle(p.id)}
                        aria-label={`${p.enabled ? 'disable' : 'enable'} pattern ${p.name}`}
                        data-testid={`scrub-patterns-toggle-${p.id}`}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </td>
                    <td>
                      <div className="scrub-patterns-name">
                        {p.name}
                        {matchN > 0 && (
                          <span
                            className="scrub-patterns-chip"
                            data-testid={`scrub-patterns-matchchip-${p.id}`}
                          >
                            {matchN} in sample
                          </span>
                        )}
                      </div>
                      <div className="scrub-patterns-id">{p.id}</div>
                    </td>
                    <td>
                      <span
                        className={`scrub-patterns-sev scrub-patterns-sev--${p.severity}`}
                        data-testid={`scrub-patterns-sev-${p.id}`}
                      >
                        ● {p.severity}
                      </span>
                    </td>
                    <td className="scrub-patterns-hits">{p.hits24h}</td>
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
