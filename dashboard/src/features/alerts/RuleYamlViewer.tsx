import { Suspense, lazy } from 'react'

// Lazy-load Monaco so the editor JS is fetched only when the alert
// detail drawer actually opens — keeps the first-paint of the Alerts
// page slim (AAASM-1394).
const Editor = lazy(() =>
  import('@monaco-editor/react').then((m) => ({ default: m.default })),
)

const HEIGHT_PX = 200

interface RuleYamlViewerProps {
  /** Pre-rendered YAML text for the alert rule snapshot. */
  yaml: string
}

/**
 * Read-only Monaco viewer for an alert-rule YAML payload (AAASM-1394).
 *
 * Renders the same `data-testid="alert-detail-rule-yaml"` as the
 * previous `<pre>` block so the AAASM-1082 Playwright spec and the
 * AAASM-1395 design-fidelity spec continue to find it. The wrapping
 * `<div>` is the only thing rendered synchronously; Monaco itself is
 * lazy-loaded inside a `<Suspense>` boundary.
 */
export function RuleYamlViewer({ yaml }: RuleYamlViewerProps) {
  return (
    <div
      data-testid="alert-detail-rule-yaml"
      style={{
        background: 'var(--surface-hover-bg)',
        borderRadius: '4px',
        overflow: 'hidden',
      }}
    >
      <Suspense
        fallback={
          <div
            data-testid="alert-detail-rule-yaml-loading"
            style={{
              padding: '0.75rem',
              fontFamily: 'ui-monospace, monospace',
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              minHeight: `${HEIGHT_PX}px`,
            }}
          >
            Loading editor…
          </div>
        }
      >
        <Editor
          height={HEIGHT_PX}
          language="yaml"
          value={yaml}
          theme="vs-dark"
          options={{
            readOnly: true,
            domReadOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            lineNumbers: 'off',
            folding: false,
            renderLineHighlight: 'none',
            scrollbar: { vertical: 'auto', horizontal: 'auto' },
            wordWrap: 'on',
            fontSize: 12,
          }}
        />
      </Suspense>
    </div>
  )
}
