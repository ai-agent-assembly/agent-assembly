import './StateView.css'

export type LoadingStatePage =
  | 'overview'
  | 'fleet'
  | 'capability'
  | 'policy'
  | 'live'
  | 'scrub'
  | 'agent'
  | 'generic'

export interface LoadingStateProps {
  page?: LoadingStatePage
}

const MATRIX_CELL_KEYS = Array.from({ length: 9 * 7 }, (_, i) => `sk-matrix-cell-${i}`)
const FLEET_ROW_KEYS = Array.from({ length: 8 }, (_, i) => `sk-fleet-row-${i}`)
const POLICY_ROW_KEYS = Array.from({ length: 6 }, (_, i) => `sk-policy-row-${i}`)
const LIVE_CARD_KEYS = Array.from({ length: 4 }, (_, i) => `sk-live-card-${i}`)
const SCRUB_ROW_KEYS = Array.from({ length: 8 }, (_, i) => `sk-scrub-row-${i}`)

function MatrixSkeleton() {
  return (
    <div className="sk-matrix">
      {MATRIX_CELL_KEYS.map((key) => (
        <div key={key} className="sk-matrix-cell">
          <span className="sk sk-line" style={{ width: '60%' }} />
        </div>
      ))}
    </div>
  )
}

function FleetSkeleton() {
  return (
    <div className="sk-table">
      {FLEET_ROW_KEYS.map((key) => (
        <div key={key} className="sk-table-row">
          <span className="sk sk-line" style={{ width: '80%' }} />
          <span className="sk sk-line" style={{ width: 60 }} />
          <span className="sk sk-line" style={{ width: 80 }} />
          <span className="sk sk-line" style={{ width: '60%' }} />
          <span className="sk sk-line" style={{ width: 50 }} />
        </div>
      ))}
    </div>
  )
}

function PolicySkeleton() {
  return (
    <div className="sk-scene sk-policy">
      <div style={{ background: 'var(--paper)', padding: 12 }}>
        {POLICY_ROW_KEYS.map((key) => (
          <div key={key} style={{ padding: '12px 8px', borderBottom: '1px solid var(--line)' }}>
            <span className="sk sk-line" style={{ width: 80, height: 8 }} />
            <div>
              <span className="sk sk-line" style={{ width: '70%', marginTop: 4 }} />
            </div>
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--paper)', padding: 16 }}>
        <div className="sk-card" style={{ height: 180, marginBottom: 12 }} />
        <div className="sk-card" style={{ height: 140 }} />
      </div>
    </div>
  )
}

function LiveSkeleton() {
  return (
    <div className="sk-scene sk-live">
      <div style={{ background: 'var(--paper)' }} />
      <div style={{ background: '#0e0e0e' }} />
      <div style={{ background: 'var(--paper)', padding: 8 }}>
        {LIVE_CARD_KEYS.map((key) => (
          <div key={key} className="sk-card" style={{ height: 80, marginBottom: 6 }} />
        ))}
      </div>
    </div>
  )
}

function ScrubSkeleton() {
  return (
    <div className="sk-scene sk-scrub">
      <div style={{ background: 'var(--paper-2)', padding: 12 }}>
        {SCRUB_ROW_KEYS.map((key) => (
          <div key={key} style={{ padding: '8px 0', borderBottom: '1px solid var(--line)' }}>
            <span className="sk sk-line" style={{ width: '70%' }} />
          </div>
        ))}
      </div>
      <div style={{ background: 'var(--paper)', padding: 16 }}>
        <div className="sk-card" style={{ height: 180, marginBottom: 12 }} />
        <div className="sk-card" style={{ height: 200 }} />
      </div>
    </div>
  )
}

function AgentSkeleton() {
  return (
    <div style={{ padding: 24 }}>
      <div className="sk-card" style={{ height: 120, marginBottom: 12 }} />
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
        <div className="sk-card" style={{ height: 280 }} />
        <div className="sk-card" style={{ height: 280 }} />
      </div>
    </div>
  )
}

export function LoadingState({ page = 'generic' }: Readonly<LoadingStateProps>) {
  return (
    <output className="state-page sk-pulse" aria-busy data-testid={`loading-state-${page}`}>
      <div className="sk-page-head">
        <div>
          <span className="sk sk-line" />
          <div>
            <span className="sk sk-line sub" />
          </div>
        </div>
        <span className="sk sk-block" style={{ width: 120 }} />
      </div>
      {page === 'capability' && <MatrixSkeleton />}
      {page === 'fleet' && <FleetSkeleton />}
      {page === 'policy' && <PolicySkeleton />}
      {page === 'live' && <LiveSkeleton />}
      {page === 'scrub' && <ScrubSkeleton />}
      {page === 'agent' && <AgentSkeleton />}
      {page === 'overview' && (
        <div style={{ padding: '20px 24px' }}>
          <span className="sk sk-block" style={{ width: '100%', height: 180 }} />
        </div>
      )}
      {page === 'generic' && (
        <div style={{ padding: '20px 24px' }}>
          <span className="sk sk-block" style={{ width: '100%' }} />
        </div>
      )}
    </output>
  )
}
