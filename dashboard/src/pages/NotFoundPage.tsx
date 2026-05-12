import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <main style={{ padding: '2rem', textAlign: 'center' }}>
      <h1>404 — Page not found</h1>
      <p>
        <Link to="/">Return to dashboard</Link>
      </p>
    </main>
  )
}
