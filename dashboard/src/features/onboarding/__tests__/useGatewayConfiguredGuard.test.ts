import { describe, it, expect, beforeEach } from 'vitest'
import {
  ONBOARDING_COMPLETED_KEY,
  clearGatewayConfigured,
  isGatewayConfigured,
  markGatewayConfigured,
} from '../useGatewayConfiguredGuard'

class MemoryStorage implements Storage {
  private store = new Map<string, string>()
  get length() { return this.store.size }
  clear() { this.store.clear() }
  getItem(k: string) { return this.store.has(k) ? this.store.get(k)! : null }
  key(i: number) { return Array.from(this.store.keys())[i] ?? null }
  removeItem(k: string) { this.store.delete(k) }
  setItem(k: string, v: string) { this.store.set(k, v) }
}

describe('useGatewayConfiguredGuard', () => {
  let storage: MemoryStorage
  beforeEach(() => {
    storage = new MemoryStorage()
  })

  it('reads false when the key is absent', () => {
    expect(isGatewayConfigured(storage)).toBe(false)
  })

  it('reads true after markGatewayConfigured', () => {
    markGatewayConfigured(storage)
    expect(storage.getItem(ONBOARDING_COMPLETED_KEY)).toBe('true')
    expect(isGatewayConfigured(storage)).toBe(true)
  })

  it('reads false after clearGatewayConfigured', () => {
    markGatewayConfigured(storage)
    clearGatewayConfigured(storage)
    expect(isGatewayConfigured(storage)).toBe(false)
  })

  it('treats non-true string values as not-configured', () => {
    storage.setItem(ONBOARDING_COMPLETED_KEY, 'false')
    expect(isGatewayConfigured(storage)).toBe(false)
    storage.setItem(ONBOARDING_COMPLETED_KEY, '1')
    expect(isGatewayConfigured(storage)).toBe(false)
  })
})
