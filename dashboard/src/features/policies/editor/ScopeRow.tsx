import { ENV_OPTS } from './constants'

interface ScopeRowProps {
  scope: string
  onScopeChange: (next: string) => void
}

/**
 * Scope card. "applies to" takes a free-form scope string; the env toggles
 * are rendered for visual fidelity to the hi-fi prototype but are currently
 * decorative — the API has no env field. Wiring them lives behind a future
 * backend extension.
 */
export function ScopeRow({ scope, onScopeChange }: ScopeRowProps) {
  return (
    <section className="editor__section" data-testid="editor-scope">
      <header className="editor__section-head">
        <h2 className="editor__section-title">Scope</h2>
      </header>
      <div className="editor__clause">
        <label className="editor__clause-label" htmlFor="editor-scope-input">
          applies to
        </label>
        <input
          id="editor-scope-input"
          className="editor__select"
          value={scope}
          onChange={(e) => onScopeChange(e.target.value)}
          data-testid="editor-scope-input"
        />
        <span className="editor__clause-label">in</span>
        {ENV_OPTS.map((env, idx) => (
          <span
            key={env}
            className="editor__select"
            aria-disabled="true"
            data-testid={`editor-scope-env-${env}`}
            style={idx === 0 ? undefined : { opacity: 0.55 }}
          >
            {env}
          </span>
        ))}
      </div>
    </section>
  )
}
