import { act, fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { OnboardingWizard } from '../OnboardingWizard'
import { probeGatewayHealth } from '../api'
import { EMPTY_STATE, type WizardState } from '../types'

// `openapi-fetch` captures `globalThis.fetch` at module load, so intercepting
// the probe is the only way to keep the wizard's step 2 off the network here
// (see `features/onboarding/api.test.tsx`).
vi.mock('../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api')>()),
  probeGatewayHealth: vi.fn(),
}))

const probe = vi.mocked(probeGatewayHealth)

const HEALTHY = {
  status: 'ok',
  version: '0.0.1',
  api_version: 'v1',
  uptime_secs: 1,
  active_connections: 0,
  pipeline_lag_ms: 0,
  checks: { storage: 'ok' },
}

const FILLED_STATE: WizardState = {
  framework: 'langchain',
  gatewayReachable: true,
  policyPreset: 'read-only',
  enrolled: true,
}

describe('OnboardingWizard step rendering', () => {
  it('renders the identity step as an explicit not-supported surface', () => {
    render(
      <OnboardingWizard
        initialStep="identity"
        initialState={{ ...FILLED_STATE, enrolled: false }}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-step-identity')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-identity-unsupported')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
  })

  it('lets the operator past the identity step, which asks nothing of them', () => {
    // AAASM-5179: the step can never be "completed", so gating Continue on it
    // would strand the wizard behind a permanently-disabled button.
    render(
      <OnboardingWizard
        initialStep="identity"
        initialState={EMPTY_STATE}
        onFinish={vi.fn()}
        onSkipAll={vi.fn()}
      />,
    )
    expect(screen.getByTestId('onboarding-continue')).not.toBeDisabled()
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
    probe.mockReset()
    probe.mockResolvedValue({ data: HEALTHY })
  })

  it('patches gatewayReachable only after the gateway itself answered ok', async () => {
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
    await act(async () => {
      fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    })
    expect(onPersist).toHaveBeenLastCalledWith(
      expect.objectContaining({ state: expect.objectContaining({ gatewayReachable: true }) }),
    )
  })

  it('leaves gatewayReachable false when the probe fails', async () => {
    probe.mockResolvedValue({ isError: true, error: new TypeError('Failed to fetch') })
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
    await act(async () => {
      fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    })
    const last = onPersist.mock.calls.at(-1)?.[0] as { state: WizardState }
    expect(last.state.gatewayReachable).toBe(false)
    expect(screen.getByTestId('onboarding-continue')).toBeDisabled()
  })

  it('patches enrolled into state when the enroll step completes', () => {
    vi.useFakeTimers()
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
    vi.useRealTimers()
  })
})
