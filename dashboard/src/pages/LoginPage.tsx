import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

export function LoginPage() {
  const navigate = useNavigate()
  const [token, setToken] = useState('')

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (token.trim()) {
      localStorage.setItem('aa_token', token.trim())
      navigate('/')
    }
  }

  return (
    <main style={{ padding: '2rem', maxWidth: '400px', margin: '4rem auto' }}>
      <h1>Agent Assembly</h1>
      <p>Enter your API token to access the governance console.</p>
      <form onSubmit={handleSubmit}>
        <label htmlFor="token" style={{ display: 'block', marginBottom: '0.5rem' }}>
          API Token
        </label>
        <input
          id="token"
          type="password"
          value={token}
          onChange={e => setToken(e.target.value)}
          placeholder="Bearer token"
          style={{ width: '100%', padding: '0.5rem', marginBottom: '1rem' }}
          autoFocus
        />
        <button type="submit" disabled={!token.trim()}>
          Sign in
        </button>
      </form>
    </main>
  )
}
