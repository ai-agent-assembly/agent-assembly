import { lazy, Suspense, useCallback, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useCreatePolicy } from '../features/policies/api'
import { useToast } from '../components/Toast'

const MonacoEditor = lazy(() => import('@monaco-editor/react'))
const DiffEditor = lazy(() =>
  import('@monaco-editor/react').then((m) => ({ default: m.DiffEditor })),
)

const EMPTY_POLICY = `# Governance policy YAML
# See: https://docs.agent-assembly.io/policies
metadata:
  name: my-policy
  version: "1.0.0"
  scope: global

rules: []
`

function validateYaml(yaml: string): string[] {
  const errors: string[] = []
  if (!yaml.trim()) {
    errors.push('Policy YAML must not be empty.')
    return errors
  }
  try {
    // Basic structural checks without importing a full YAML parser.
    // Real parse validation happens server-side on apply.
    const lines = yaml.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      // Detect tab indentation which YAML forbids
      if (/^\t/.test(line)) {
        errors.push(`Line ${i + 1}: YAML must not use tab indentation.`)
      }
      // Detect unmatched braces (simple heuristic)
      const opens = (line.match(/\{/g) ?? []).length
      const closes = (line.match(/\}/g) ?? []).length
      if (opens !== closes) {
        errors.push(`Line ${i + 1}: Unbalanced curly braces.`)
      }
    }
    if (!yaml.includes('metadata:')) errors.push("Missing required 'metadata' section.")
    if (!yaml.includes('rules:')) errors.push("Missing required 'rules' section.")
  } catch {
    errors.push('YAML structure is invalid.')
  }
  return errors
}

export function PolicyEditorPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { toast } = useToast()
  const createPolicy = useCreatePolicy()

  const originalName = searchParams.get('name')
  const originalVersion = searchParams.get('version')

  const [yaml, setYaml] = useState(EMPTY_POLICY)
  const [validationErrors, setValidationErrors] = useState<string[]>(() => validateYaml(EMPTY_POLICY))
  const [showDiff, setShowDiff] = useState(false)
  // Store the "before" snapshot for the diff view; never mutated after mount.
  const [originalYaml] = useState(EMPTY_POLICY)

  // Debounced validation
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const handleChange = useCallback((value: string | undefined) => {
    const v = value ?? ''
    setYaml(v)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      setValidationErrors(validateYaml(v))
    }, 400)
  }, [])

  const hasErrors = validationErrors.length > 0

  async function handleApply() {
    if (hasErrors) return
    try {
      await createPolicy.mutateAsync({ policy_yaml: yaml })
      toast('Policy applied successfully.', 'success')
      navigate('/policies')
    } catch {
      toast('Failed to apply policy. Check the YAML and try again.', 'error')
    }
  }

  function handleDiscard() {
    if (yaml === originalYaml || window.confirm('Discard unsaved changes?')) {
      navigate('/policies')
    }
  }

  return (
    <main style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }} data-testid="policy-editor">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 style={{ margin: 0 }}>
          {originalName ? `Edit: ${originalName} v${originalVersion ?? ''}` : 'New Policy'}
        </h1>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            data-testid="toggle-diff-btn"
            onClick={() => setShowDiff((v) => !v)}
            style={{ padding: '0.5rem 1rem', borderRadius: '0.375rem', border: '1px solid #d1d5db', cursor: 'pointer' }}
          >
            {showDiff ? 'Editor' : 'Diff'}
          </button>
          <button
            data-testid="discard-btn"
            onClick={handleDiscard}
            style={{ padding: '0.5rem 1rem', borderRadius: '0.375rem', border: '1px solid #d1d5db', cursor: 'pointer' }}
          >
            Discard
          </button>
          <button
            data-testid="apply-btn"
            onClick={() => void handleApply()}
            disabled={hasErrors || createPolicy.isPending}
            style={{
              padding: '0.5rem 1rem',
              borderRadius: '0.375rem',
              background: hasErrors ? '#9ca3af' : '#2563eb',
              color: '#fff',
              border: 'none',
              cursor: hasErrors ? 'not-allowed' : 'pointer',
              fontWeight: 600,
            }}
          >
            {createPolicy.isPending ? 'Applying…' : 'Apply'}
          </button>
        </div>
      </div>

      {hasErrors && (
        <ul
          data-testid="validation-errors"
          style={{
            margin: 0,
            padding: '0.75rem 1rem',
            background: '#fef2f2',
            border: '1px solid #fca5a5',
            borderRadius: '0.375rem',
            listStyle: 'disc',
            paddingLeft: '2rem',
            color: '#dc2626',
            fontSize: '0.875rem',
          }}
        >
          {validationErrors.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      )}

      <div style={{ border: '1px solid #e5e7eb', borderRadius: '0.375rem', overflow: 'hidden', height: '60vh' }}>
        <Suspense fallback={<div style={{ padding: '1rem' }} data-testid="editor-loading">Loading editor…</div>}>
          {showDiff ? (
            <DiffEditor
              height="60vh"
              language="yaml"
              original={originalYaml}
              modified={yaml}
              options={{ readOnly: false, renderSideBySide: true }}
            />
          ) : (
            <MonacoEditor
              height="60vh"
              language="yaml"
              value={yaml}
              onChange={handleChange}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                tabSize: 2,
                wordWrap: 'on',
              }}
            />
          )}
        </Suspense>
      </div>

    </main>
  )
}
