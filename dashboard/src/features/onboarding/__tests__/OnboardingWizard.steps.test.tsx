import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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

  it('skip-step on the final step finishes the wizard', () => {
    const onFinish = vi.fn()
    render(
      <OnboardingWizard
        initialStep="enroll"
        initialState={FILLED_STATE}
        onFinish={onFinish}
        onSkipAll={vi.fn()}
      />,
    )
    fireEvent.click(screen.getByTestId('onboarding-skip-step'))
    expect(onFinish).toHaveBeenCalledWith(FILLED_STATE)
  })
})

describe('OnboardingWizard step → state patching', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.runOnlyPendingTimers()
    vi.useRealTimers()
  })

  it('patches installVerified into state when the install step verifies', () => {
    const onPersist = vi.fn()
    render(
      <OnboardingWizard
        initialStep="install"
        initialState={EMPTY_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
        onPersist={onPersist}
      />,
    )
    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    act(() => {
      vi.advanceTimersByTime(600)
    })
    expect(onPersist).toHaveBeenLastCalledWith(
      expect.objectContaining({ state: expect.objectContaining({ installVerified: true }) }),
    )
  })

  it('patches the generated identity into state on the identity step', () => {
    const onPersist = vi.fn()
    render(
      <OnboardingWizard
        initialStep="identity"
        initialState={EMPTY_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
        onPersist={onPersist}
      />,
    )
    fireEvent.click(screen.getByTestId('onboarding-identity-generate'))
    act(() => {
      vi.advanceTimersByTime(800)
    })
    const last = onPersist.mock.calls.at(-1)![0]
    expect(last.state.identity).not.toBeNull()
    expect(last.state.identity.alg).toBe('Ed25519')
  })

  it('patches enrolled into state when the enroll step completes', () => {
    const onPersist = vi.fn()
    render(
      <OnboardingWizard
        initialStep="enroll"
        initialState={EMPTY_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
        onPersist={onPersist}
      />,
    )
    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))
    act(() => {
      vi.advanceTimersByTime(800)
    })
    expect(onPersist).toHaveBeenLastCalledWith(
      expect.objectContaining({ state: expect.objectContaining({ enrolled: true }) }),
    )
  })
})
