import { useId, useState } from 'react'
import { API_KEY_SCOPES, type ApiKeyScope, type GenerateApiKeyInput } from './types'

export interface GenerateKeyDialogProps {
  open: boolean
  onClose: () => void
  onSubmit: (input: GenerateApiKeyInput) => void | Promise<void>
  isSubmitting?: boolean
}

export function GenerateKeyDialog(props: GenerateKeyDialogProps) {
  if (!props.open) return null
  return <GenerateKeyDialogBody {...props} />
}

function GenerateKeyDialogBody({ onClose, onSubmit, isSubmitting }: GenerateKeyDialogProps) {
  const [label, setLabel] = useState('')
  const [scopes, setScopes] = useState<ApiKeyScope[]>([])
  const [touched, setTouched] = useState(false)
  const labelId = useId()

  const trimmed = label.trim()
  const labelValid = trimmed.length > 0
  const scopesValid = scopes.length > 0
  const showLabelError = touched && !labelValid
  const showScopesError = touched && !scopesValid

  function toggleScope(scope: ApiKeyScope) {
    setScopes((prev) => (prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]))
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setTouched(true)
    if (!labelValid || !scopesValid) return
    void onSubmit({ label: trimmed, scopes })
  }

  return (
    <div className="iam-dialog__backdrop" role="dialog" aria-modal="true" aria-labelledby={`${labelId}-title`} data-testid="generate-key-dialog">
      <form className="iam-dialog" onSubmit={handleSubmit}>
        <h2 id={`${labelId}-title`} className="iam-dialog__title">Generate API key</h2>

        <label htmlFor={labelId} className="iam-dialog__label">Label</label>
        <input
          id={labelId}
          autoFocus
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={() => setTouched(true)}
          aria-invalid={showLabelError}
          aria-describedby={showLabelError ? `${labelId}-error` : undefined}
          className="iam-dialog__input"
          data-testid="generate-key-label-input"
          placeholder="ci-runner"
          required
        />
        {showLabelError && (
          <div id={`${labelId}-error`} className="iam-dialog__error" data-testid="generate-key-label-error">
            Label is required.
          </div>
        )}

        <div className="iam-dialog__label">Scopes</div>
        <div className="iam-scope-checklist" data-testid="generate-key-scopes">
          {API_KEY_SCOPES.map((s) => (
            <label key={s} className="iam-scope-checklist__row">
              <input
                type="checkbox"
                checked={scopes.includes(s)}
                onChange={() => toggleScope(s)}
                data-testid={`generate-key-scope-${s}`}
              />
              <span className="iam-scope-checklist__name">{s}</span>
            </label>
          ))}
        </div>
        {showScopesError && (
          <div className="iam-dialog__error" data-testid="generate-key-scopes-error">
            Select at least one scope.
          </div>
        )}

        <div className="iam-dialog__actions">
          <button type="button" className="iam-dialog__btn" onClick={onClose} data-testid="generate-key-cancel">
            Cancel
          </button>
          <button
            type="submit"
            className="iam-dialog__btn iam-dialog__btn--primary"
            disabled={isSubmitting}
            data-testid="generate-key-submit"
          >
            {isSubmitting ? 'Generating…' : 'Generate key'}
          </button>
        </div>
      </form>
    </div>
  )
}
