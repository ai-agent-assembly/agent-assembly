import { Link } from 'react-router-dom'
import { usePoliciesQuery, type Policy } from '../features/policies/api'

function ActiveBadge({ active }: { active: boolean }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        color: '#fff',
        background: active ? '#16a34a' : '#6b7280',
      }}
    >
      {active ? 'active' : 'inactive'}
    </span>
  )
}

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 3 }).map((_, i) => (
        <tr key={i} data-testid="policy-row-skeleton">
          {Array.from({ length: 4 }).map((_, j) => (
            <td key={j} style={{ padding: '0.5rem' }}>
              <span
                style={{
                  display: 'block',
                  height: '1rem',
                  background: '#e5e7eb',
                  borderRadius: '4px',
                }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

function PolicyRow({ policy }: { policy: Policy }) {
  return (
    <tr data-testid="policy-row" style={{ borderBottom: '1px solid #f3f4f6' }}>
      <td style={{ padding: '0.5rem' }}>
        <Link to={`/policies/editor?name=${encodeURIComponent(policy.name)}&version=${encodeURIComponent(policy.version)}`}>
          {policy.name}
        </Link>
      </td>
      <td style={{ padding: '0.5rem' }}>{policy.version}</td>
      <td style={{ padding: '0.5rem' }}>{policy.rule_count}</td>
      <td style={{ padding: '0.5rem' }}>
        <ActiveBadge active={policy.active} />
      </td>
    </tr>
  )
}

export function PoliciesPage() {
  const { data: policies, isLoading, isError, refetch } = usePoliciesQuery()

  return (
    <main style={{ padding: '1.5rem' }} data-testid="policies-page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h1 style={{ margin: 0 }}>Policies</h1>
        <Link
          to="/policies/editor"
          data-testid="new-policy-btn"
          style={{
            padding: '0.5rem 1rem',
            background: '#2563eb',
            color: '#fff',
            borderRadius: '0.375rem',
            textDecoration: 'none',
            fontSize: '0.875rem',
            fontWeight: 600,
          }}
        >
          New policy
        </Link>
      </div>

      {isError && (
        <div
          data-testid="policies-error"
          style={{ color: '#dc2626', marginBottom: '1rem', display: 'flex', gap: '1rem', alignItems: 'center' }}
        >
          <span>Failed to load policies.</span>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      {!isLoading && !isError && policies?.length === 0 && (
        <p data-testid="policies-empty">
          No policies found.{' '}
          <Link to="/policies/editor">Create your first policy →</Link>
        </p>
      )}

      <table data-testid="policies-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {['Name', 'Version', 'Rules', 'Status'].map((h) => (
              <th
                key={h}
                style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #e5e7eb' }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            <SkeletonRows />
          ) : (
            policies?.map((policy) => <PolicyRow key={`${policy.name}-${policy.version}`} policy={policy} />)
          )}
        </tbody>
      </table>
    </main>
  )
}
