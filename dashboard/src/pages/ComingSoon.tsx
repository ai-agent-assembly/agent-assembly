import { Link, useLocation } from 'react-router-dom'

/**
 * Placeholder page rendered for canonical AAASM-94 routes that
 * are wired but whose feature implementation lands in a later
 * Subtask. Keeps the nav and routing surface complete so users
 * never hit a 404 inside the shell (AAASM-94 AC #5, #6).
 */
export function ComingSoon({ name }: { name?: string }) {
  const location = useLocation()
  const fromPath = location.pathname.replace(/^\//, '').replace(/-/g, ' ')
  const heading = name ?? (fromPath || 'this page')

  return (
    <main
      data-testid="coming-soon"
      data-route={location.pathname}
      style={{ padding: '2rem', maxWidth: '40rem' }}
    >
      <h1 style={{ marginTop: 0, textTransform: 'capitalize' }}>{heading}</h1>
      <p style={{ color: 'var(--shell-text-muted)', fontSize: '0.95rem' }}>
        This page is part of the governance dashboard but is not implemented yet.
        Track progress under the AAASM-94 Story.
      </p>
      <p style={{ marginTop: '1.5rem', fontSize: '0.9rem' }}>
        <Link to="/">← Back to dashboard</Link>
      </p>
    </main>
  )
}
