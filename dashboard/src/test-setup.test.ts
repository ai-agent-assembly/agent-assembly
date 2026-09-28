import NVMRC from '../.nvmrc?raw'
import pkg from '../package.json'

// AAASM-6198: the storage installed by test-setup.ts replaces the host's, so it
// has to be shown to be a real Storage rather than a stub that accepts writes
// and quietly loses them. Every assertion below is a property the six test files
// that were failing on Node 26 actually depend on.
describe.each([
  ['localStorage', () => globalThis.localStorage],
  ['sessionStorage', () => globalThis.sessionStorage],
])('%s', (_name, get) => {
  beforeEach(() => {
    get().clear()
  })

  it('is defined and exposes the whole Storage method surface', () => {
    const s = get()
    expect(s).toBeDefined()
    for (const member of ['getItem', 'setItem', 'removeItem', 'clear', 'key'] as const) {
      expect(typeof s[member]).toBe('function')
    }
    expect(typeof s.length).toBe('number')
  })

  it('reads back exactly what it wrote', () => {
    get().setItem('aa_probe', 'written')
    expect(get().getItem('aa_probe')).toBe('written')
  })

  it('returns null rather than undefined for an absent key', () => {
    // `undefined` is what the broken Node 26 path produced one level up, and a
    // stub returning it here would make callers that check `=== null` wrong.
    expect(get().getItem('aa_never_written')).toBeNull()
  })

  it('removes and clears', () => {
    get().setItem('a', '1')
    get().setItem('b', '2')
    expect(get().length).toBe(2)
    get().removeItem('a')
    expect(get().getItem('a')).toBeNull()
    expect(get().length).toBe(1)
    get().clear()
    expect(get().length).toBe(0)
    expect(get().getItem('b')).toBeNull()
  })

  it('stringifies values and keys, as Web Storage does', () => {
    const s = get() as unknown as { setItem(k: unknown, v: unknown): void }
    s.setItem('n', 42)
    expect(get().getItem('n')).toBe('42')
    s.setItem(7, 'seven')
    expect(get().getItem('7')).toBe('seven')
  })

  it('enumerates keys by index and reports null out of range', () => {
    get().setItem('first', '1')
    get().setItem('second', '2')
    expect([get().key(0), get().key(1)]).toEqual(['first', 'second'])
    expect(get().key(2)).toBeNull()
    expect(get().key(-1)).toBeNull()
  })

  it('is reachable identically through window and globalThis', () => {
    // The six failing files reach storage through `globalThis`; product code in
    // useTheme.ts and tokenStorage.ts uses the bare global. Both must be the
    // same store or a test's setup would not be seen by the code under test.
    get().setItem('aa_same', 'yes')
    const viaWindow = (window as unknown as Record<string, Storage>)[_name]
    expect(viaWindow.getItem('aa_same')).toBe('yes')
  })
})

it('keeps localStorage and sessionStorage as separate stores', () => {
  // tokenStorage.ts purges a pre-AAASM-4322 token from localStorage while
  // reading the live one from sessionStorage, so conflating the two would make
  // that test pass for the wrong reason.
  globalThis.localStorage.clear()
  globalThis.sessionStorage.clear()
  globalThis.localStorage.setItem('shared_key', 'from_local')
  globalThis.sessionStorage.setItem('shared_key', 'from_session')
  expect(globalThis.localStorage.getItem('shared_key')).toBe('from_local')
  expect(globalThis.sessionStorage.getItem('shared_key')).toBe('from_session')
})

// AAASM-6198: the declared Node floor is consumed by test-setup.ts at runtime,
// so a drift between the two places it is written down would silently disable
// the guard that makes an unsupported Node visible.
describe('declared Node version', () => {
  it('declares a floor in dashboard/package.json engines.node', () => {
    expect(pkg.engines?.node).toBe('>=22')
  })

  it('pins the same major in .nvmrc as engines.node requires', () => {
    // .nvmrc lives next to package.json rather than at the repository root so
    // that it sits inside the Vite root and this drift check can actually read
    // it — Vite denies importing outside the package ("Denied ID"). It is also
    // where it belongs: the constraint is a property of this package.
    const nvmrcMajor = NVMRC.trim()
    const enginesMajor = /(\d+)/.exec(pkg.engines.node)?.[1]
    expect(nvmrcMajor).toBe(enginesMajor)
  })
})
