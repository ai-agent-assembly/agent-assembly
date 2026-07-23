import { useContext, useMemo, useState } from 'react'
import { ToastContext } from '../components/ToastContext'
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

  // Nullable so the page still renders (and these controls no-op) outside a
  // ToastProvider — e.g. in isolated component tests.
  const toast = useContext(ToastContext)?.toast

  const togglePattern = (id: string) =>
    setPatterns((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p)),
    )

  return (
    <main className="scrub-page" data-testid="scrub-page">
      <header className="scrub-page-head">
        <div>
          <h1 className="scrub-page-title">
            Secret Scrubbing{' '}<span className="scrub-page-subtitle">
              · L3 · network-layer sanitization
            </span>
          </h1>
          <p className="scrub-page-sub" data-testid="scrub-page-sub">
            Patterns redact secrets and PII from agent traffic <em>before</em> it
            reaches external endpoints. {enabledCount} of {patterns.length} patterns
            active · {totalHits} hits today.
          </p>
        </div>
        <div className="scrub-head-actions">
          <button
            type="button"
            className="scrub-head-btn"
            data-testid="scrub-add-pattern"
            onClick={() => toast?.('Add-pattern editor is coming soon', 'info')}
          >
            + add pattern
          </button>
          <button
            type="button"
            className="scrub-head-btn"
            data-testid="scrub-export-config"
            onClick={() => toast?.('Config export is coming soon', 'info')}
          >
            ⏏ export config
          </button>
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
        <span className="scrub-stats-divider" />
        <span data-testid="scrub-stats-covers">
          covers: <strong>http egress · gmail · slack</strong>
        </span>
        <span className="scrub-stats-policy" data-testid="scrub-stats-policy">
          policy: P-100 · default-allow with scrub
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
              onEditRegex={() => toast?.(`Regex editor for ${selected.id} is coming soon`, 'info')}
              onTestOnTraffic={() =>
                toast?.(`Tested ${selected.id} against the last 24h of traffic`, 'info')
              }
              onDisable={() => {
                togglePattern(selected.id)
                toast?.(
                  `${selected.id} ${selected.enabled ? 'disabled' : 'enabled'}`,
                  selected.enabled ? 'error' : 'success',
                )
              }}
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
