import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'

export function LoginPage() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [apiKey, setApiKey] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await login(apiKey.trim())
      navigate('/')
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <main style={{ padding: '2rem', maxWidth: '400px', margin: '4rem auto' }}>
      <h1>Agent Assembly</h1>
      <p>Enter your API key to access the governance console.</p>
      <form onSubmit={handleSubmit}>
        <label htmlFor="apiKey" style={{ display: 'block', marginBottom: '0.5rem' }}>
          API Key
        </label>
        <input
          id="apiKey"
          type="password"
          value={apiKey}
          onChange={e => setApiKey(e.target.value)}
          placeholder="aa_…"
          style={{ width: '100%', padding: '0.5rem', marginBottom: '1rem' }}
          autoFocus
        />
        {error && <p style={{ color: 'red', marginBottom: '1rem' }}>{error}</p>}
        <button type="submit" disabled={!apiKey.trim() || loading}>
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
