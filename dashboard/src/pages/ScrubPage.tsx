import { useMemo, useState } from 'react'
import { PATTERNS, SAMPLE_PAYLOAD } from '../features/scrub/fixtures'
import { PatternsLibrary } from '../features/scrub/PatternsLibrary'
import { PatternDetail } from '../features/scrub/PatternDetail'
import { PayloadDiff } from '../features/scrub/PayloadDiff'
import { countMatchesByPattern, tokenize } from '../features/scrub/tokenize'
import type { ScrubPattern } from '../features/scrub/types'
import './ScrubPage.css'

export function ScrubPage() {
  const [patterns, setPatterns] = useState<ScrubPattern[]>(PATTERNS)
  const [selectedId, setSelectedId] = useState<string>('OPENAI_KEY')
  const [payload, setPayload] = useState<string>(SAMPLE_PAYLOAD)
  const [detailCollapsed, setDetailCollapsed] = useState<boolean>(false)

  const tokens = useMemo(() => tokenize(payload, patterns), [payload, patterns])
  const matchCounts = useMemo(() => countMatchesByPattern(tokens), [tokens])

  const enabled = patterns.filter((p) => p.enabled)
  const totalHits = enabled.reduce((s, p) => s + p.hits24h, 0)
  const enabledCount = enabled.length

  const selected = patterns.find((p) => p.id === selectedId) ?? patterns[0]

  const togglePattern = (id: string) =>
    setPatterns((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p)),
    )

  return (
    <main className="scrub-page" data-testid="scrub-page">
      <header className="scrub-page-head">
        <div>
          <h1 className="scrub-page-title">
            Secret Scrubbing
            <span className="scrub-page-subtitle">
              · L3 · network-layer sanitization
            </span>
          </h1>
          <p className="scrub-page-sub" data-testid="scrub-page-sub">
            Patterns redact secrets and PII from agent traffic <em>before</em> it
            reaches external endpoints. {enabledCount} of {patterns.length} patterns
            active · {totalHits} hits today.
          </p>
        </div>
      </header>

      <div className="scrub-stats" role="status" aria-live="polite">
        <span className="scrub-stats-item">
          posture: <strong className="scrub-stats-ok">● 0 leaks (30d)</strong>
        </span>
        <span className="scrub-stats-divider" />
        <span className="scrub-stats-scrubbed" data-testid="scrub-stats-stripped">
          ● {totalHits} stripped / 24h
        </span>
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-enabled-count">
          {enabledCount}/{patterns.length} patterns enabled
        </span>
      </div>

      <div className="scrub-body">
        <PatternsLibrary
          patterns={patterns}
          selectedId={selected?.id ?? ''}
          onSelect={setSelectedId}
          onToggle={togglePattern}
          matchCounts={matchCounts}
        />

        <div className="scrub-right">
          {selected && (
            <PatternDetail
              pattern={selected}
              collapsed={detailCollapsed}
              onToggleCollapsed={() => setDetailCollapsed((c) => !c)}
            />
          )}
          <PayloadDiff
            payload={payload}
            onPayloadChange={setPayload}
            tokens={tokens}
            patterns={patterns}
            matchCounts={matchCounts}
          />
        </div>
      </div>
    </main>
  )
}
