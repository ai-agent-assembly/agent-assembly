import './StateView.css'

export type LoadingStatePage = 'overview' | 'fleet' | 'capability' | 'generic'

export interface LoadingStateProps {
  page?: LoadingStatePage
}

function MatrixSkeleton() {
  const cells = Array.from({ length: 9 * 7 })
  return (
    <div className="sk-matrix">
      {cells.map((_, i) => (
        <div key={i} className="sk-matrix-cell">
          <span className="sk sk-line" style={{ width: '60%' }} />
        </div>
      ))}
    </div>
  )
}

function FleetSkeleton() {
  return (
    <div className="sk-table">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="sk-table-row">
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

export function LoadingState({ page = 'generic' }: LoadingStateProps) {
  return (
    <div className="state-page sk-pulse" role="status" aria-busy data-testid={`loading-state-${page}`}>
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
    </div>
  )
}
