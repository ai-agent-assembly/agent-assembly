/* global React */
/*
 * design/v3 hi-fi — Login / Authentication (AAASM-5438)
 *
 * Authoritative in-repo design source for the OSS dashboard login page
 * (dashboard/src/pages/LoginPage.tsx). Supersedes the cross-repo reference the
 * implementation previously cited (agent-assembly-cloud/design/hi-fi/
 * saas-shell.jsx → LoginPage), which is not resolvable for OSS design-QA.
 *
 * The login surface is DRIVEN BY `GET /api/v1/auth/methods` (ADR 0031 D2/§Q5) —
 * it renders from the deployment's real capability signal, never a guess, and
 * never shows a form the backend cannot serve. Two states, both authoritative:
 *
 *   A. methods = ["api_key"]            — in-memory / SQLite deployment
 *   B. methods = ["api_key","password"] — Postgres-backed deployment
 *
 * Hard constraints (ADR 0031 D4, verified live 2026-08-03 against both
 * deployments):
 *   - NO OAuth / social login anywhere (no Google/GitHub button).
 *   - NO "or continue with email" divider.
 *   - Sign-up collects email + password ONLY — NO workspace / organisation /
 *     team-name field (OSS is single-workspace).
 *   - The API-key path is always reachable in both states.
 */

const { useState } = React;

/* Shared brand header — identical in both states. */
function BrandHeader() {
  return (
    <header className="login-page__brand">
      <div className="login-page__brand-mark" aria-hidden="true">aa</div>
      <h1 className="login-page__brand-title">Agent Assembly</h1>
      <p className="login-page__brand-tagline">Governance-native AI agent runtime</p>
    </header>
  );
}

/*
 * State A — api_key-only (in-memory / SQLite).
 * A single API-key field + an honest note that account login needs Postgres.
 * No password form, no social buttons, no divider.
 */
function ApiKeyOnly() {
  return (
    <section className="login-page__card" role="region" aria-label="Authentication">
      <p className="login-page__note">
        Account login (email &amp; password) needs a Postgres-backed deployment.
        This instance runs in-memory, so sign in with an API key below.
      </p>
      <label className="login-page__label" htmlFor="apikey">API key</label>
      <input id="apikey" type="password" placeholder="aa_…" className="login-page__input" />
      <button type="submit" className="login-page__submit">Sign in with API key</button>
    </section>
  );
}

/*
 * State B — password-enabled (Postgres).
 * Two tabs: Sign in / Sign up. Email + password only. "Remember me" on sign-in.
 * A reachable "Sign in with an API key instead" affordance. No social, no
 * divider, no workspace field on sign-up.
 */
function AccountAuth() {
  const [tab, setTab] = useState('signin'); // 'signin' | 'signup'
  return (
    <section className="login-page__card" role="region" aria-label="Authentication">
      <div className="login-page__tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'signin'} className="login-page__tab"
          onClick={() => setTab('signin')}>Sign in</button>
        <button role="tab" aria-selected={tab === 'signup'} className="login-page__tab"
          onClick={() => setTab('signup')}>Sign up</button>
      </div>

      <form className="login-page__form">
        <label className="login-page__label" htmlFor="email">Email</label>
        <input id="email" type="email" placeholder="you@company.com" className="login-page__input" />

        <label className="login-page__label" htmlFor="password">Password</label>
        <input id="password" type="password" placeholder="••••••••" className="login-page__input" />

        {/* Remember-me only on the sign-in tab. NO workspace/org field on sign-up. */}
        {tab === 'signin' && (
          <label className="login-page__remember">
            <input type="checkbox" /> Remember me
          </label>
        )}

        <button type="submit" className="login-page__submit">
          {tab === 'signin' ? 'Sign in' : 'Sign up'}
        </button>
      </form>

      {/* Tab cross-link + API-key fallback. No social buttons, no divider. */}
      <p className="login-page__switch">
        {tab === 'signin'
          ? <>New here? <button className="login-page__switch-btn" onClick={() => setTab('signup')}>Sign up</button></>
          : <>Have an account? <button className="login-page__switch-btn" onClick={() => setTab('signin')}>Sign in</button></>}
      </p>
      <button type="button" className="login-page__apikey-link">Sign in with an API key instead</button>
    </section>
  );
}

/* Preview harness: flip `methods` to see each authoritative state. */
function LoginPage({ methods = ['api_key', 'password'] }) {
  const passwordEnabled = methods.includes('password');
  return (
    <main aria-label="Sign in" className="login-page">
      <BrandHeader />
      {passwordEnabled ? <AccountAuth /> : <ApiKeyOnly />}
    </main>
  );
}

// eslint-disable-next-line no-undef
if (typeof module !== 'undefined') module.exports = { LoginPage, AccountAuth, ApiKeyOnly };
