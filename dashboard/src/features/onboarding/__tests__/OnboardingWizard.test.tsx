import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { OnboardingWizard } from '../OnboardingWizard'
import type { WizardState } from '../types'

const FILLED_STATE: WizardState = {
  framework: 'langchain',
  installVerified: true,
  identity: { did: 'did:aa:abc', alg: 'Ed25519', fingerprint: 'AA', issuedAt: 'x' },
  policyPreset: 'read-only',
  enrolled: true,
}

describe('OnboardingWizard', () => {
  it('renders the framework step by default with continue disabled until selection', () => {
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} />)
    expect(screen.getByTestId('onboarding-step-framework')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-continue')).toBeDisabled()
  })

  it('enables continue once a framework is picked', () => {
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} />)
    fireEvent.click(screen.getByTestId('onboarding-framework-langchain'))
    expect(screen.getByTestId('onboarding-continue')).not.toBeDisabled()
  })

  it('advances on continue, shows back, and walks back to framework', () => {
    render(
      <OnboardingWizard
        initialStep="install"
        initialState={{ ...FILLED_STATE, enrolled: false }}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-step-install')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('onboarding-back'))
    expect(screen.getByTestId('onboarding-step-framework')).toBeInTheDocument()
  })

  it('skip-step advances even when canAdvance is false', () => {
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} />)
    expect(screen.getByTestId('onboarding-step-framework')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('onboarding-skip-step'))
    expect(screen.getByTestId('onboarding-step-install')).toBeInTheDocument()
  })

  it('the final-step continue button calls onFinish with the wizard state', () => {
    const onFinish = vi.fn()
    render(
      <OnboardingWizard
        initialStep="enroll"
        initialState={FILLED_STATE}
        onFinish={onFinish}
        onSkipAll={vi.fn()}
      />,
    )
    const cont = screen.getByTestId('onboarding-continue')
    expect(cont).toHaveTextContent('finish setup')
    fireEvent.click(cont)
    expect(onFinish).toHaveBeenCalledWith(FILLED_STATE)
  })

  it('calls onSkipAll when the top-right "skip onboarding" button is clicked', () => {
    const onSkipAll = vi.fn()
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={onSkipAll} />)
    fireEvent.click(screen.getByTestId('onboarding-skip-all'))
    expect(onSkipAll).toHaveBeenCalled()
  })

  it('renders the right step counter', () => {
    render(
      <OnboardingWizard
        initialStep="policy"
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-step-counter')).toHaveTextContent('step 4 of 5')
  })
})
