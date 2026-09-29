// Vite builds this into a real, same-origin asset and hands back a constructor
// that instantiates it from that asset's URL.
//
// The specifier is relative to `esm/vs/`, not to the package root: monaco-editor
// 0.57 maps `"./*.js": "./esm/vs/*.js"` in its `exports`, where 0.55 mapped
// `"./*": "./*"`. So `esm/vs/editor/editor.worker.js` — correct on 0.55 —
// resolves to `esm/vs/esm/vs/editor/editor.worker.js` on 0.57 and fails.
import EditorWorker from 'monaco-editor/editor/editor.worker.js?worker'

/** The one member of Monaco's `Environment` this dashboard sets. */
interface MonacoWorkerEnvironment {
  getWorker(workerId: string, label: string): Worker
}

/**
 * Give Monaco a same-origin web worker, so it never falls back to a `blob:` one
 * that index.html's CSP forbids (AAASM-6233).
 *
 * Monaco reads `globalThis.MonacoEnvironment` when it needs its editor worker.
 * With nothing there it builds a bootstrap script in memory, wraps it in a
 * `Blob`, and starts the worker from the resulting `blob:` URL. index.html's
 * `script-src 'self'` (AAASM-4322) sets no `worker-src`, so `script-src` is the
 * fallback for workers and a `blob:` URL is not `'self'` — the browser blocks
 * the worker and Monaco surfaces uncaught errors on the Alerts drawer.
 *
 * The fix is to satisfy the policy as written rather than widen it: a worker
 * Vite emits into `dist/assets/` is served from the dashboard's own origin, so
 * `'self'` covers it.
 *
 * Only the base `editor.worker` is wired up. It is the worker Monaco starts for
 * every model; the per-language service workers are separate entry points this
 * dashboard does not ship (YAML highlighting is Monarch, which runs on the main
 * thread, and `monaco-yaml` is not a dependency). `getWorker` therefore ignores
 * `label` — there is exactly one worker to hand back.
 */
export function configureMonacoWorkers(): void {
  const scope = globalThis as { MonacoEnvironment?: MonacoWorkerEnvironment }
  scope.MonacoEnvironment = {
    getWorker: () => new EditorWorker(),
  }
}
