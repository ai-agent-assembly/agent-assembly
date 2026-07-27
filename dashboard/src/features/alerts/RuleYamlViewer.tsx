import { loader } from '@monaco-editor/react'
import { Suspense, lazy } from 'react'
import { useTheme } from '../../theme/useTheme'

// Monaco's runtime is imported dynamically, inside the same lazy boundary as
// `@monaco-editor/react` itself, so it is fetched only when the alert detail
// drawer actually opens — keeps the first-paint of the Alerts page slim
// (AAASM-1394). A static top-level `import * as monaco from 'monaco-editor'`
// pulled the whole Monaco module graph into every bundle that merely imports
// this file, including jsdom test suites that never render it — and
// Monaco's own module-init code calls `document.queryCommandSupported`,
// which jsdom does not implement, breaking unrelated Alerts-feature tests.
//
// `loader.config` still points @monaco-editor/react at this npm-bundled
// runtime instead of its default jsDelivr CDN fetch — index.html's
// `script-src 'self'` CSP (AAASM-4322) blocks that fetch — but the config
// call is deferred until Monaco is actually being loaded, before Editor
// resolves.
const Editor = lazy(async () => {
  const [monaco, { default: MonacoEditor }] = await Promise.all([
    import('monaco-editor'),
    import('@monaco-editor/react'),
  ])
  loader.config({ monaco })
  return { default: MonacoEditor }
})

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
export function RuleYamlViewer({ yaml }: Readonly<RuleYamlViewerProps>) {
  // Follow the dashboard's active theme so the editor doesn't render a dark
  // box inside the otherwise-light UI in light mode (AAASM-3507). 'vs' is
  // Monaco's built-in light theme; the repo registers no custom light theme.
  const { theme } = useTheme()
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
          theme={theme === 'dark' ? 'vs-dark' : 'vs'}
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
