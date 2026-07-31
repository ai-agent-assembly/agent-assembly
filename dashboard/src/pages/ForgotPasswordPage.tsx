/**
 * Password-reset flow (AAASM-5307), reachable from the login page's "Forgot?"
 * link (ADR 0031 §Q4).
 *
 * Two forms on one route:
 *  1. Request — enter an email → `POST /auth/password/reset`. The response is
 *     enumeration-safe by contract (`202` regardless of whether the email
 *     exists), so the UI always shows the same neutral "if that email exists, a
 *     link was sent" message and never signals account existence.
 *  2. Confirm — enter the reset token + a new password →
 *     `POST /auth/password/reset/confirm`. The token normally arrives via the
 *     emailed link (`?token=…`); it also prefills from the query string.
 *
 * The new password is only held in transient React state and is never
 * persisted (security rule 7).
 */

import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { AuthApiError, confirmPasswordReset, requestPasswordReset } from '../auth/authApi'

type Mode = 'request' | 'confirm'

const MIN_PASSWORD_LENGTH = 8

const NEUTRAL_RESET_MESSAGE =
  'If that email matches an account, a password-reset link has been sent. Check your inbox.'

export function ForgotPasswordPage() {
  const [params] = useSearchParams()
  const tokenFromLink = params.get('token')

  // A token in the URL means the operator followed the emailed link → confirm.
  const [mode, setMode] = useState<Mode>(tokenFromLink ? 'confirm' : 'request')

  useEffect(() => {
    if (tokenFromLink) setMode('confirm')
  }, [tokenFromLink])

  return (
    <main aria-label="Reset password" className="login-page">
      <header className="login-page__brand">
        <div className="login-page__brand-mark" aria-hidden="true">
          aa
        </div>
        <h1 className="login-page__brand-title">Reset your password</h1>
      </header>

      <section className="login-page__card" role="region" aria-label="Password reset">
        {mode === 'request' ? (
          <RequestForm onHasToken={() => setMode('confirm')} />
        ) : (
          <ConfirmForm initialToken={tokenFromLink ?? ''} />
        )}
        <p className="login-page__switch">
          <Link to="/login" className="login-page__switch-btn">
            Back to sign in
          </Link>
        </p>
      </section>
    </main>
  )
}

/** Step 1: request a reset link. Always ends on the same neutral message. */
function RequestForm({ onHasToken }: Readonly<{ onHasToken: () => void }>) {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setLoading(true)
    try {
      await requestPasswordReset(email.trim())
    } finally {
      // Enumeration-safe: succeed or fail, we surface the identical neutral
      // outcome and never disclose whether the email matched an account.
      setSent(true)
      setLoading(false)
    }
  }

  if (sent) {
    return (
      <>
        <p role="status" className="login-page__notice">
          {NEUTRAL_RESET_MESSAGE}
        </p>
        <p className="login-page__switch">
          Already have a reset link?{' '}
          <button type="button" className="login-page__switch-btn" onClick={onHasToken}>
            Enter it here
          </button>
        </p>
      </>
    )
  }

  return (
    <>
      <p className="login-page__note">
        Enter the email for your account and we&apos;ll send a reset link.
      </p>
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
        <button type="submit" className="login-page__submit" disabled={loading}>
          {loading ? 'Sending…' : 'Send reset link'}
        </button>
      </form>
      <p className="login-page__switch">
        Already have a reset link?{' '}
        <button type="button" className="login-page__switch-btn" onClick={onHasToken}>
          Enter it here
        </button>
      </p>
    </>
  )
}

/** Step 2: set a new password from the emailed token. */
function ConfirmForm({ initialToken }: Readonly<{ initialToken: string }>) {
  const [token, setToken] = useState(initialToken)
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  useEffect(() => {
    if (initialToken) setToken(initialToken)
  }, [initialToken])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
      return
    }

    setLoading(true)
    try {
      await confirmPasswordReset(token.trim(), password)
      setDone(true)
    } catch (err) {
      setError(err instanceof AuthApiError ? err.message : 'Something went wrong. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  if (done) {
    return (
      <p role="status" className="login-page__notice">
        Your password has been reset.{' '}
        <Link to="/login" className="login-page__switch-btn">
          Sign in
        </Link>
      </p>
    )
  }

  return (
    <>
      <p className="login-page__note">
        Paste the reset token from your email and choose a new password.
      </p>
      <form onSubmit={handleSubmit} className="login-page__form" noValidate>
        <label className="login-page__field">
          <span>Reset token</span>
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste your reset token"
            required
            autoComplete="off"
          />
        </label>
        <label className="login-page__field">
          <span>New password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            minLength={MIN_PASSWORD_LENGTH}
            autoComplete="new-password"
          />
        </label>
        {error && (
          <p role="alert" className="login-page__error">
            {error}
          </p>
        )}
        <button
          type="submit"
          className="login-page__submit"
          disabled={loading || token.trim().length === 0}
        >
          {loading ? 'Resetting…' : 'Reset password'}
        </button>
      </form>
    </>
  )
}
