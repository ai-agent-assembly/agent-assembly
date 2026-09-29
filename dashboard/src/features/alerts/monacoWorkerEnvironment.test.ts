import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { configureMonacoWorkers } from './monacoWorkerEnvironment'

// What Monaco reads. Declared here rather than imported so the assertions are
// about the shape Monaco actually looks for (`globalThis.MonacoEnvironment`
// with a `getWorker`), not about a type the module under test exports.
type MonacoScope = {
  MonacoEnvironment?: { getWorker?: (workerId: string, label: string) => unknown }
}

interface Construction {
  url: string
  options: unknown
}

let constructed: Construction[]

beforeEach(() => {
  constructed = []
  // Monaco never constructs the worker itself — it calls `getWorker` and the
  // returned object is a `Worker`. Standing in for the constructor is what lets
  // this test see *which URL* the worker would be started from, which is the
  // entire question (AAASM-6233).
  vi.stubGlobal(
    'Worker',
    class {
      constructor(url: string | URL, options?: unknown) {
        constructed.push({ url: String(url), options })
      }
    },
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  delete (globalThis as MonacoScope).MonacoEnvironment
})

describe('configureMonacoWorkers', () => {
  it('installs a getWorker on globalThis.MonacoEnvironment, which is where Monaco looks', () => {
    expect((globalThis as MonacoScope).MonacoEnvironment).toBeUndefined()

    configureMonacoWorkers()

    // `globalThis.MonacoEnvironment` specifically: monaco-editor's
    // `getMonacoEnvironment()` (vs/base/browser/browser.js) returns exactly
    // that property, and returning undefined from it is what sends Monaco down
    // the blob-worker fallback.
    expect(typeof (globalThis as MonacoScope).MonacoEnvironment?.getWorker).toBe('function')
  })

  it('starts the worker from a bundled same-origin asset, never a blob: URL', () => {
    configureMonacoWorkers()
    const getWorker = (globalThis as MonacoScope).MonacoEnvironment?.getWorker
    if (!getWorker) throw new Error('getWorker was not installed')

    // Monaco's own call shape: (workerId, label).
    getWorker('workerMain.js', 'editorWorkerService')

    expect(constructed).toHaveLength(1)
    const { url, options } = constructed[0]

    // The defect this guards: with no MonacoEnvironment, Monaco assembles a
    // bootstrap script, wraps it in a Blob and starts the worker from
    // `URL.createObjectURL(blob)`. index.html's `script-src 'self'` sets no
    // `worker-src`, so `script-src` is the fallback for workers and a `blob:`
    // URL is not `'self'` — the browser blocks it.
    expect(url.startsWith('blob:')).toBe(false)
    expect(url.startsWith('data:')).toBe(false)

    // ...and the positive half: it is Monaco's editor worker, resolved to a
    // path the bundler emitted, not a CDN URL. @monaco-editor/react's own
    // default is a jsDelivr fetch, which the same CSP directive forbids.
    expect(url).toMatch(/editor\.worker/)
    expect(url).not.toMatch(/^https?:\/\//)

    // Deliberately no assertion on `options.type`. Whether the worker is a
    // module or a classic script is Vite's `worker.format` decision and it
    // differs between the dev/test transform (module) and `vite build`
    // (iife, self-contained) — pinning it here would assert a fact about the
    // transform this test happens to run under, not about the app. What CSP
    // cares about, and what this test therefore pins, is the origin of the URL.
    expect(options).not.toBeNull()
  })

  it('hands back one worker regardless of the label Monaco asks for', () => {
    configureMonacoWorkers()
    const getWorker = (globalThis as MonacoScope).MonacoEnvironment?.getWorker
    if (!getWorker) throw new Error('getWorker was not installed')

    // Only the base editor worker is wired up; this dashboard ships no
    // per-language service worker. Asking under any label must still yield a
    // worker rather than throwing, or the blocked-worker symptom returns as an
    // unhandled rejection instead.
    getWorker('workerMain.js', 'editorWorkerService')
    getWorker('workerMain.js', 'yaml')

    expect(constructed).toHaveLength(2)
    expect(constructed[0].url).toBe(constructed[1].url)
  })
})
