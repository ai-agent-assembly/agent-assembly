import { describe, it, expect } from 'vitest'
import { EMPTY_STATE, type WizardState } from '../types'
import {
  canAdvance,
  isFinalStep,
  nextStep,
  prevStep,
  stepIndex,
  stepStatus,
} from '../wizardState'

describe('wizardState helpers', () => {
  describe('canAdvance', () => {
    it('blocks every step on EMPTY_STATE', () => {
      expect(canAdvance(EMPTY_STATE, 'framework')).toBe(false)
      expect(canAdvance(EMPTY_STATE, 'install')).toBe(false)
      expect(canAdvance(EMPTY_STATE, 'identity')).toBe(false)
      expect(canAdvance(EMPTY_STATE, 'policy')).toBe(false)
      expect(canAdvance(EMPTY_STATE, 'enroll')).toBe(false)
    })

    it('unblocks each step when its slice of state is set', () => {
      const filled: WizardState = {
        framework: 'langchain',
        installVerified: true,
        identity: { did: 'did:aa:abc', alg: 'Ed25519', fingerprint: 'AA', issuedAt: 'x' },
        policyPreset: 'read-only',
        enrolled: true,
      }
      expect(canAdvance(filled, 'framework')).toBe(true)
      expect(canAdvance(filled, 'install')).toBe(true)
      expect(canAdvance(filled, 'identity')).toBe(true)
      expect(canAdvance(filled, 'policy')).toBe(true)
      expect(canAdvance(filled, 'enroll')).toBe(true)
    })
  })

  describe('nextStep / prevStep', () => {
    it('walks forward through the 5 steps', () => {
      expect(nextStep('framework')).toBe('install')
      expect(nextStep('install')).toBe('identity')
      expect(nextStep('identity')).toBe('policy')
      expect(nextStep('policy')).toBe('enroll')
    })

    it('returns null past the final step', () => {
      expect(nextStep('enroll')).toBe(null)
    })

    it('walks backward through the 5 steps', () => {
      expect(prevStep('install')).toBe('framework')
      expect(prevStep('identity')).toBe('install')
      expect(prevStep('policy')).toBe('identity')
      expect(prevStep('enroll')).toBe('policy')
    })

    it('returns null before the first step', () => {
      expect(prevStep('framework')).toBe(null)
    })
  })

  describe('isFinalStep / stepIndex', () => {
    it('returns true only for the last step', () => {
      expect(isFinalStep('framework')).toBe(false)
      expect(isFinalStep('enroll')).toBe(true)
    })

    it('returns 0-based step index', () => {
      expect(stepIndex('framework')).toBe(0)
      expect(stepIndex('enroll')).toBe(4)
    })
  })

  describe('stepStatus', () => {
    it('marks earlier steps done, current step current, later steps future', () => {
      expect(stepStatus('framework', 'identity')).toBe('done')
      expect(stepStatus('install', 'identity')).toBe('done')
      expect(stepStatus('identity', 'identity')).toBe('current')
      expect(stepStatus('policy', 'identity')).toBe('future')
      expect(stepStatus('enroll', 'identity')).toBe('future')
    })
  })
})
