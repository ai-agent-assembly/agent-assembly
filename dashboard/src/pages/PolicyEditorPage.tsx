import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { DiffEditor } from '@monaco-editor/react'
import type { OnMount, Monaco } from '@monaco-editor/react'
import { useCreatePolicy, usePolicyByVersion } from '../features/policies/api'
import { useToast } from '../components/Toast'

type EditorInstance = Parameters<OnMount>[0]

const MonacoEditor = lazy(() => import('@monaco-editor/react'))

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
    const lines = yaml.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      if (/^\t/.test(line)) {
        errors.push(`Line ${i + 1}: YAML must not use tab indentation.`)
      }
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

  // Fetch the live policy version when name+version are present in the URL.
  const { data: livePolicy } = usePolicyByVersion(originalName, originalVersion)

  const [yaml, setYaml] = useState(EMPTY_POLICY)
  // The "live" YAML — used as the diff baseline and Discard target.
  // Mutated only when the hook resolves with a new policy.
  const [liveYaml, setLiveYaml] = useState(EMPTY_POLICY)
  const [validationErrors, setValidationErrors] = useState<string[]>(() => validateYaml(EMPTY_POLICY))

  // When the live policy resolves, sync both the editor and the diff baseline.
  // Setting state inside this effect is intentional — we need to react to the
  // async query result. Guarded so it only fires when the live YAML changes.
  useEffect(() => {
    if (!livePolicy?.policy_yaml) return
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setYaml(livePolicy.policy_yaml)
    setLiveYaml(livePolicy.policy_yaml)
    setValidationErrors(validateYaml(livePolicy.policy_yaml))
  }, [livePolicy])

  // Debounced validation
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Monaco editor + monaco namespace, captured on mount for setModelMarkers
  const editorRef = useRef<EditorInstance | null>(null)
  const monacoRef = useRef<Monaco | null>(null)

  const handleChange = useCallback((value: string | undefined) => {
    const v = value ?? ''
    setYaml(v)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      setValidationErrors(validateYaml(v))
    }, 500)
  }, [])

  const hasErrors = validationErrors.length > 0

  const applyMarkers = useCallback((errors: string[], source: string) => {
    const editor = editorRef.current
    const monaco = monacoRef.current
    if (!editor || !monaco) return
    const model = editor.getModel()
    if (!model) return
    const lines = source.split('\n')
    const markers = errors.map((msg) => {
      const lineMatch = msg.match(/^Line (\d+):/)
      const lineNum = lineMatch ? Math.max(1, parseInt(lineMatch[1], 10)) : 1
      const lineContent = lines[lineNum - 1] ?? ''
      return {
        startLineNumber: lineNum,
        endLineNumber: lineNum,
        startColumn: 1,
        endColumn: Math.max(lineContent.length + 1, 2),
        message: msg,
        severity: monaco.MarkerSeverity.Error,
      }
    })
    monaco.editor.setModelMarkers(model, 'policy-validator', markers)
  }, [])

  useEffect(() => {
    applyMarkers(validationErrors, yaml)
  }, [validationErrors, yaml, applyMarkers])

  const handleEditorMount: OnMount = useCallback((editor, monaco) => {
    editorRef.current = editor
    monacoRef.current = monaco
  }, [])

  function handleValidate() {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    setValidationErrors(validateYaml(yaml))
  }

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
    // Reset editor draft back to the live YAML — stay on the page.
    setYaml(liveYaml)
    setValidationErrors(validateYaml(liveYaml))
  }

  return (
    <main
      style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}
      data-testid="policy-editor"
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 style={{ margin: 0 }}>
          {originalName ? `Edit: ${originalName} v${originalVersion ?? ''}` : 'New Policy'}
        </h1>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            data-testid="validate-btn"
            onClick={handleValidate}
            style={{ padding: '0.5rem 1rem', borderRadius: '0.375rem', border: '1px solid #d1d5db', cursor: 'pointer' }}
          >
            Validate
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

      <Suspense fallback={<div style={{ padding: '1rem' }} data-testid="editor-loading">Loading editor…</div>}>
        <div style={{ display: 'flex', gap: '0.5rem', height: '60vh' }}>
          <div
            data-testid="policy-editor-pane"
            style={{ flex: 1, border: '1px solid #e5e7eb', borderRadius: '0.375rem', overflow: 'hidden' }}
          >
            <MonacoEditor
              height="60vh"
              language="yaml"
              value={yaml}
              onChange={handleChange}
              onMount={handleEditorMount}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                tabSize: 2,
                wordWrap: 'on',
              }}
            />
          </div>
          <div
            data-testid="policy-diff-pane"
            style={{ flex: 1, border: '1px solid #e5e7eb', borderRadius: '0.375rem', overflow: 'hidden' }}
          >
            <DiffEditor
              height="60vh"
              language="yaml"
              original={liveYaml}
              modified={yaml}
              options={{ readOnly: true, renderSideBySide: false }}
            />
          </div>
        </div>
      </Suspense>
    </main>
  )
}
