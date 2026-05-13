import { describe, it, expect } from 'vitest'
import {
  ONBOARDING_SESSION_KEY,
  clearWizardSession,
  loadWizardSession,
  resolveInitialSession,
  saveWizardSession,
} from '../useWizardSession'
import { EMPTY_STATE, type WizardState } from '../types'

class MemoryStorage implements Storage {
  private store = new Map<string, string>()
  get length() { return this.store.size }
  clear() { this.store.clear() }
  getItem(k: string) { return this.store.has(k) ? this.store.get(k)! : null }
  key(i: number) { return Array.from(this.store.keys())[i] ?? null }
  removeItem(k: string) { this.store.delete(k) }
  setItem(k: string, v: string) { this.store.set(k, v) }
}

const FILLED_STATE: WizardState = {
  framework: 'langchain',
  installVerified: true,
  identity: { did: 'did:aa:abc', alg: 'Ed25519', fingerprint: 'AA:BB', issuedAt: 'x' },
  policyPreset: 'read-only',
  enrolled: false,
}

describe('useWizardSession storage helpers', () => {
  it('returns null when no session is persisted', () => {
    const s = new MemoryStorage()
    expect(loadWizardSession(s)).toBe(null)
  })

  it('round-trips step + state through save / load', () => {
    const s = new MemoryStorage()
    saveWizardSession({ step: 'identity', state: FILLED_STATE }, s)
    const loaded = loadWizardSession(s)
    expect(loaded).toEqual({ step: 'identity', state: FILLED_STATE })
  })

  it('clearWizardSession removes the persisted entry', () => {
    const s = new MemoryStorage()
    saveWizardSession({ step: 'install', state: EMPTY_STATE }, s)
    clearWizardSession(s)
    expect(loadWizardSession(s)).toBe(null)
  })

  it('returns null for malformed JSON', () => {
    const s = new MemoryStorage()
    s.setItem(ONBOARDING_SESSION_KEY, '{not json')
    expect(loadWizardSession(s)).toBe(null)
  })

  it('returns null when the persisted step id is unknown', () => {
    const s = new MemoryStorage()
    s.setItem(
      ONBOARDING_SESSION_KEY,
      JSON.stringify({ step: 'unknown-step', state: EMPTY_STATE }),
    )
    expect(loadWizardSession(s)).toBe(null)
  })

  it('returns null when state is missing required slice keys', () => {
    const s = new MemoryStorage()
    s.setItem(
      ONBOARDING_SESSION_KEY,
      JSON.stringify({ step: 'framework', state: { framework: 'langchain' } }),
    )
    expect(loadWizardSession(s)).toBe(null)
  })

  it('resolveInitialSession falls back to step framework + EMPTY_STATE when nothing persisted', () => {
    const s = new MemoryStorage()
    expect(resolveInitialSession(s)).toEqual({
      step: 'framework',
      state: EMPTY_STATE,
    })
  })

  it('resolveInitialSession returns the persisted session when present', () => {
    const s = new MemoryStorage()
    saveWizardSession({ step: 'policy', state: FILLED_STATE }, s)
    expect(resolveInitialSession(s)).toEqual({
      step: 'policy',
      state: FILLED_STATE,
    })
  })
})
