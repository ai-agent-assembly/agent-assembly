import '@testing-library/jest-dom'

// AAASM-6198: give every test a working Web Storage regardless of the host Node.
//
// Node shipped experimental Web Storage globals, and from Node 26 they win over
// jsdom's on the vitest global object: vitest's jsdom environment copies jsdom's
// window properties onto `globalThis` but leaves keys the host already defines
// alone, and Node defines both `localStorage` and `sessionStorage`. Measured
// inside the configured environment:
//
//   Node 22.23.2 -> sessionStorage instanceof Storage === true   (jsdom's)
//   Node 26.8.1  -> sessionStorage instanceof Storage === false  (Node's own)
//
// `localStorage` is the one that breaks loudly, because Node's getter returns
// `undefined` unless the process was started with `--localstorage-file`
// ("ExperimentalWarning: localStorage is not available because
// --localstorage-file was not provided"). That made 32 tests across six
// unrelated files fail with `Cannot read properties of undefined (reading
// 'removeItem')`. `sessionStorage` breaks silently instead — it works, but it is
// Node's process-wide store rather than jsdom's per-environment one.
//
// Both names are therefore replaced with one implementation, so the suite
// exercises the same storage on every Node rather than jsdom's on some versions
// and Node's on others. `window` is the same object as `globalThis` here, so a
// single definition covers both access paths. The native property is an accessor
// but `configurable: true`, which is what makes this legal.
//
// Deliberately not done: passing `--localstorage-file`, which would only help
// people who know to pass it; and patching the six failing test files, which
// would leave the next test that touches storage with the same trap.
function createStorage(): Storage {
  const entries = new Map<string, string>()
  return {
    get length(): number {
      return entries.size
    },
    clear(): void {
      entries.clear()
    },
    getItem(key: string): string | null {
      const k = String(key)
      // Web Storage returns null, never undefined, for an absent key.
      return entries.has(k) ? entries.get(k)! : null
    },
    key(index: number): string | null {
      const keys = Array.from(entries.keys())
      return index >= 0 && index < keys.length ? keys[index] : null
    },
    removeItem(key: string): void {
      entries.delete(String(key))
    },
    setItem(key: string, value: string): void {
      // Web Storage stringifies both key and value.
      entries.set(String(key), String(value))
    },
  }
}

for (const name of ['localStorage', 'sessionStorage'] as const) {
  const storage = createStorage()
  Object.defineProperty(globalThis, name, {
    configurable: true,
    enumerable: false,
    get: () => storage,
  })
}
