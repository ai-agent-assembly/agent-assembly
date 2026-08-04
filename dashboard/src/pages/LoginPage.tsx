/**
 * Login page (AAASM-5307).
 *
 * Ports the cloud two-tab sign-in / sign-up UX
 * (`agent-assembly-cloud/design/hi-fi/saas-shell.jsx` → LoginPage) onto the OSS
 * dashboard, with **all OAuth / social login removed** (ADR 0031 D4): no
 * Google/GitHub buttons and no "or continue with email" divider.
 *
 * Honest degradation (ADR 0031 D2 / §Q5): the page reads
 * `GET /api/v1/auth/methods` on mount and renders from that signal, never a
 * guess. When the deployment advertises `password` (Postgres-backed) it shows
 * the two-tab email/password UI, with the API-key path still reachable. When it
 * advertises only `api_key` (in-memory) it renders the API-key form plus a note
 * that account login needs a Postgres-backed deployment — it never shows a
 * password form the backend cannot serve.
 */

import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { authMethods, AuthApiError, type AuthMethod } from '../auth/authApi'
import { useAuth } from '../auth/useAuth'

type Tab = 'signin' | 'signup'

const MIN_PASSWORD_LENGTH = 8

function messageFor(err: unknown): string {
  if (err instanceof AuthApiError) return err.message
  return 'Something went wrong. Please try again.'
}

export function LoginPage() {
  const navigate = useNavigate()
  const { login, loginWithCredentials, signup } = useAuth()

  // `null` while the capability probe is in flight; an array once known.
  const [methods, setMethods] = useState<AuthMethod[] | null>(null)

  useEffect(() => {
    let cancelled = false
    authMethods()
      .then((m) => {
        if (!cancelled) setMethods(m)
      })
      .catch(() => {
        // If the probe fails, degrade to the always-present API-key path rather
        // than blocking sign-in entirely.
        if (!cancelled) setMethods(['api_key'])
      })
    return () => {
      cancelled = true
    }
  }, [])

  const passwordAuthEnabled = methods?.includes('password') ?? false

  if (methods === null) {
    return (
      <main className="login-page" aria-busy="true">
        <p className="login-page__brand-tagline">Loading…</p>
      </main>
    )
  }

  return (
    <main aria-label="Sign in" className="login-page">
      <header className="login-page__brand">
        <div className="login-page__brand-mark" aria-hidden="true">
          aa
        </div>
        <h1 className="login-page__brand-title">Agent Assembly</h1>
        <p className="login-page__brand-tagline">Governance-native AI agent runtime</p>
      </header>

      <section className="login-page__card" aria-label="Authentication">
        {passwordAuthEnabled ? (
          <AccountAuth
            onSignIn={loginWithCredentials}
            onSignUp={signup}
            onApiKey={login}
            onAuthenticated={() => navigate('/')}
          />
        ) : (
          <ApiKeyOnly onApiKey={login} onAuthenticated={() => navigate('/')} />
        )}
      </section>
    </main>
  )
}

/** Two-tab email/password UI with a reachable API-key affordance. */
function AccountAuth({
  onSignIn,
  onSignUp,
  onApiKey,
  onAuthenticated,
}: Readonly<{
  onSignIn: (email: string, password: string, rememberMe: boolean) => Promise<void>
  onSignUp: (email: string, password: string) => Promise<void>
  onApiKey: (apiKey: string) => Promise<void>
  onAuthenticated: () => void
}>) {
  const [tab, setTab] = useState<Tab>('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showApiKey, setShowApiKey] = useState(false)

  function switchTab(next: Tab) {
    setTab(next)
    setError(null)
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
      return
    }

    setLoading(true)
    try {
      if (tab === 'signin') {
        await onSignIn(email.trim(), password, rememberMe)
      } else {
        await onSignUp(email.trim(), password)
      }
      onAuthenticated()
    } catch (err) {
      setError(messageFor(err))
    } finally {
      setLoading(false)
    }
  }

  let submitLabel: string
  if (loading) {
    submitLabel = tab === 'signin' ? 'Signing in…' : 'Creating account…'
  } else {
    submitLabel = tab === 'signin' ? 'Sign in' : 'Create account'
  }

  return (
    <>
      <div className="login-page__tabs" role="tablist" aria-label="Sign in or sign up">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'signin'}
          className={`login-page__tab ${tab === 'signin' ? 'login-page__tab--active' : ''}`}
          onClick={() => switchTab('signin')}
        >
          Sign in
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'signup'}
          className={`login-page__tab ${tab === 'signup' ? 'login-page__tab--active' : ''}`}
          onClick={() => switchTab('signup')}
        >
          Sign up
        </button>
      </div>

      <form onSubmit={handleSubmit} className="login-page__form" noValidate>
        <label className="login-page__field">
          <span>Work email</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            required
            autoComplete="email"
          />
        </label>
        <div className="login-page__field">
          <div className="login-page__field-header">
            <span id="password-label">Password</span>
            {tab === 'signin' && (
              <Link to="/forgot-password" className="login-page__forgot">
                Forgot?
              </Link>
            )}
          </div>
          <input
            aria-labelledby="password-label"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            minLength={MIN_PASSWORD_LENGTH}
            autoComplete={tab === 'signin' ? 'current-password' : 'new-password'}
          />
        </div>

        {tab === 'signin' && (
          <label className="login-page__remember">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              autoComplete="off"
            />
            <span>Remember me for 30 days</span>
          </label>
        )}

        {error && (
          <p role="alert" className="login-page__error">
            {error}
          </p>
        )}

        <button type="submit" className="login-page__submit" disabled={loading}>
          {submitLabel}
        </button>
      </form>

      <p className="login-page__switch">
        {tab === 'signin' ? 'No account? ' : 'Have an account? '}
        <button
          type="button"
          className="login-page__switch-btn"
          onClick={() => switchTab(tab === 'signin' ? 'signup' : 'signin')}
        >
          {tab === 'signin' ? 'Sign up' : 'Sign in'}
        </button>
      </p>

      <hr className="login-page__divider" />
      {showApiKey ? (
        <ApiKeyForm onApiKey={onApiKey} onAuthenticated={onAuthenticated} />
      ) : (
        <p className="login-page__switch login-page__apikey-toggle">
          <button
            type="button"
            className="login-page__switch-btn"
            onClick={() => setShowApiKey(true)}
          >
            Sign in with an API key instead
          </button>
        </p>
      )}
    </>
  )
}

/** API-key-only surface for in-memory deployments (honest degradation). */
function ApiKeyOnly({
  onApiKey,
  onAuthenticated,
}: Readonly<{
  onApiKey: (apiKey: string) => Promise<void>
  onAuthenticated: () => void
}>) {
  return (
    <>
      <p className="login-page__note">
        Account login (email &amp; password) needs a Postgres-backed deployment. This
        instance runs in-memory, so sign in with an API key below.
      </p>
      <ApiKeyForm onApiKey={onApiKey} onAuthenticated={onAuthenticated} autoFocus />
    </>
  )
}

/** Shared API-key entry form — the OSS auth path that always survives. */
function ApiKeyForm({
  onApiKey,
  onAuthenticated,
  autoFocus = false,
}: Readonly<{
  onApiKey: (apiKey: string) => Promise<void>
  onAuthenticated: () => void
  autoFocus?: boolean
}>) {
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await onApiKey(apiKey.trim())
      onAuthenticated()
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="login-page__form login-page__apikey" noValidate>
      <label className="login-page__field">
        <span>API key</span>
        <input
          id="apiKey"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="aa_…"
          autoComplete="off"
          autoFocus={autoFocus}
        />
      </label>
      {error && (
        <p role="alert" className="login-page__error">
          {error}
        </p>
      )}
      <button type="submit" className="login-page__submit" disabled={!apiKey.trim() || loading}>
        {loading ? 'Signing in…' : 'Sign in with API key'}
      </button>
    </form>
  )
}
