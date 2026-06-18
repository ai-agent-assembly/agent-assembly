import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { OnboardingWizard } from '../OnboardingWizard'
import { EMPTY_STATE, type WizardState } from '../types'

const FILLED_STATE: WizardState = {
  framework: 'langchain',
  installVerified: true,
  identity: { did: 'did:aa:abc', alg: 'Ed25519', fingerprint: 'AA', issuedAt: 'x' },
  policyPreset: 'read-only',
  enrolled: true,
}

describe('OnboardingWizard step rendering', () => {
  it('renders the identity step when the wizard starts there', () => {
    render(
      <OnboardingWizard
        initialStep="identity"
        initialState={{ ...FILLED_STATE, enrolled: false }}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-step-identity')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-identity-issued')).toBeInTheDocument()
  })

  it('renders the policy step', () => {
    render(
      <OnboardingWizard
        initialStep="policy"
        initialState={FILLED_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-step-policy')).toBeInTheDocument()
  })

  it('renders the enroll step', () => {
    render(
      <OnboardingWizard
        initialStep="enroll"
        initialState={FILLED_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-step-enroll')).toBeInTheDocument()
  })

  it('fires onPersist with the current step and state on mount and after navigation', () => {
    const onPersist = vi.fn()
    render(
      <OnboardingWizard
        initialStep="install"
        initialState={{ ...FILLED_STATE, enrolled: false }}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
        onPersist={onPersist}
      />,
    )
    expect(onPersist).toHaveBeenCalledWith(
      expect.objectContaining({ step: 'install' }),
    )

    fireEvent.click(screen.getByTestId('onboarding-continue'))
    expect(onPersist).toHaveBeenCalledWith(
      expect.objectContaining({ step: 'identity' }),
    )
  })

  it('persists framework selection into wizard state via the step onChange', () => {
    const onPersist = vi.fn()
    render(
      <OnboardingWizard
        initialState={EMPTY_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
        onPersist={onPersist}
      />,
    )
    fireEvent.click(screen.getByTestId('onboarding-framework-langchain'))
    expect(onPersist).toHaveBeenLastCalledWith(
      expect.objectContaining({ state: expect.objectContaining({ framework: 'langchain' }) }),
    )
  })
})
