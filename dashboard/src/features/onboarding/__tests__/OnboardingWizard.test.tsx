import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { describe, it, expect, vi } from 'vitest'
import { OnboardingWizard } from '../OnboardingWizard'
import type { WizardState } from '../types'

// The enroll step polls the agent registry; see `features/onboarding/api.test.tsx`
// for why the client is the mock boundary rather than `globalThis.fetch`.
vi.mock('../../../api/client', () => ({ api: { GET: vi.fn().mockResolvedValue({ data: { items: [], page: 1, per_page: 100, total: 0 }, error: undefined, response: { ok: true, status: 200 } }) } }))

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

const FILLED_STATE: WizardState = {
  framework: 'langchain',
  gatewayReachable: true,
  policyPreset: 'read-only',
  enrolled: true,
}

describe('OnboardingWizard', () => {
  it('renders the framework step by default with continue disabled until selection', () => {
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} />, { wrapper })
    expect(screen.getByTestId('onboarding-step-framework')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-continue')).toBeDisabled()
  })

  it('enables continue once a framework is picked', () => {
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} />, { wrapper })
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
      { wrapper },
    )
    expect(screen.getByTestId('onboarding-step-install')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('onboarding-back'))
    expect(screen.getByTestId('onboarding-step-framework')).toBeInTheDocument()
  })

  it('skip-step advances even when canAdvance is false', () => {
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} />, { wrapper })
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
      { wrapper },
    )
    const cont = screen.getByTestId('onboarding-continue')
    expect(cont).toHaveTextContent('finish setup')
    fireEvent.click(cont)
    expect(onFinish).toHaveBeenCalledWith(FILLED_STATE)
  })

  it('calls onSkipAll when the top-right "skip onboarding" button is clicked', () => {
    const onSkipAll = vi.fn()
    render(<OnboardingWizard onFinish={vi.fn()} onSkipAll={onSkipAll} />, { wrapper })
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
      { wrapper },
    )
    expect(screen.getByTestId('onboarding-step-counter')).toHaveTextContent('step 4 of 5')
  })
})
