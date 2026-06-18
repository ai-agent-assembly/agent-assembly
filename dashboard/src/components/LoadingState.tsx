import './StateView.css'

export type LoadingStatePage = 'overview' | 'fleet' | 'capability' | 'generic'

export interface LoadingStateProps {
  page?: LoadingStatePage
}

const MATRIX_CELL_KEYS = Array.from({ length: 9 * 7 }, (_, i) => `sk-matrix-cell-${i}`)
const FLEET_ROW_KEYS = Array.from({ length: 8 }, (_, i) => `sk-fleet-row-${i}`)

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
