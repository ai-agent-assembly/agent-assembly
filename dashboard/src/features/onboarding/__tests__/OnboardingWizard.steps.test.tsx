import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { OnboardingWizard } from '../OnboardingWizard'
import { api } from '../../../api/client'
import { probeGatewayHealth } from '../api'
import { EMPTY_STATE, type WizardState } from '../types'

// Both boundaries are mocked for the same reason: `openapi-fetch` captures
// `globalThis.fetch` at module load, so intercepting the client is the only way
// to keep these tests off the network (see `features/onboarding/api.test.tsx`).
vi.mock('../../../api/client', () => ({ api: { GET: vi.fn() } }))
vi.mock('../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api')>()),
  probeGatewayHealth: vi.fn(),
}))

const apiGet = api.GET as unknown as ReturnType<typeof vi.fn>
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
  gatewayHealthy: true,
  policyPreset: 'read-only',
  enrolled: true,
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function renderWizard(props: Partial<React.ComponentProps<typeof OnboardingWizard>> = {}) {
  return render(
    <OnboardingWizard onFinish={vi.fn()} onSkipAll={vi.fn()} {...props} />,
    { wrapper },
  )
}

beforeEach(() => {
  apiGet.mockReset()
  apiGet.mockResolvedValue({
    data: { items: [], page: 1, per_page: 100, total: 0 },
    error: undefined,
    response: { ok: true, status: 200 } as Response,
  })
  probe.mockReset()
  probe.mockResolvedValue({ data: HEALTHY })
})

describe('OnboardingWizard step rendering', () => {
  it('renders the identity step as an explicit not-supported surface', () => {
    renderWizard({ initialStep: 'identity', initialState: { ...FILLED_STATE, enrolled: false } })

    expect(screen.getByTestId('onboarding-step-identity')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-identity-unsupported')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
  })

  it('lets the operator past the identity step, which asks nothing of them', () => {
    // AAASM-5179: the step can never be "completed", so gating Continue on it
    // would strand the wizard behind a permanently-disabled button.
    renderWizard({ initialStep: 'identity', initialState: EMPTY_STATE })

    expect(screen.getByTestId('onboarding-continue')).not.toBeDisabled()
  })

  it('renders the policy step', () => {
    renderWizard({ initialStep: 'policy', initialState: FILLED_STATE })
    expect(screen.getByTestId('onboarding-step-policy')).toBeInTheDocument()
  })

  it('renders the enroll step', () => {
    renderWizard({ initialStep: 'enroll', initialState: FILLED_STATE })
    expect(screen.getByTestId('onboarding-step-enroll')).toBeInTheDocument()
  })

  it('fires onPersist with the current step and state on mount and after navigation', () => {
    const onPersist = vi.fn()
    renderWizard({
      initialStep: 'install',
      initialState: { ...FILLED_STATE, enrolled: false },
      onPersist,
    })
    expect(onPersist).toHaveBeenCalledWith(expect.objectContaining({ step: 'install' }))

    fireEvent.click(screen.getByTestId('onboarding-continue'))
    expect(onPersist).toHaveBeenCalledWith(expect.objectContaining({ step: 'identity' }))
  })

  it('persists framework selection into wizard state via the step onChange', () => {
    const onPersist = vi.fn()
    renderWizard({ initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-framework-langchain'))
    expect(onPersist).toHaveBeenLastCalledWith(
      expect.objectContaining({ state: expect.objectContaining({ framework: 'langchain' }) }),
    )
  })

  it('skip-step on the final step finishes the wizard', () => {
    const onFinish = vi.fn()
    renderWizard({ initialStep: 'enroll', initialState: FILLED_STATE, onFinish })

    fireEvent.click(screen.getByTestId('onboarding-skip-step'))
    expect(onFinish).toHaveBeenCalledWith(FILLED_STATE)
  })
})

describe('OnboardingWizard step → state patching', () => {
  it('patches gatewayHealthy only after the gateway itself answered ok', async () => {
    const onPersist = vi.fn()
    renderWizard({ initialStep: 'install', initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-install-verify'))

    await waitFor(() =>
      expect(onPersist).toHaveBeenLastCalledWith(
        expect.objectContaining({ state: expect.objectContaining({ gatewayHealthy: true }) }),
      ),
    )
  })

  it('clears gatewayHealthy when a re-check fails after a good probe', async () => {
    // The footer must not still read "✓ ready to continue" over a red
    // UNAVAILABLE transcript, and the stale `true` must not reach localStorage.
    probe.mockResolvedValueOnce({ data: HEALTHY })
    probe.mockResolvedValueOnce({ isError: true, error: new TypeError('Failed to fetch') })
    const onPersist = vi.fn()
    renderWizard({ initialStep: 'install', initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    await screen.findByTestId('onboarding-install-ok')
    expect(screen.getByTestId('onboarding-continue')).not.toBeDisabled()

    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    await screen.findByTestId('onboarding-install-absent')

    const last = onPersist.mock.calls.at(-1)?.[0] as { state: WizardState }
    expect(last.state.gatewayHealthy).toBe(false)
    expect(screen.getByTestId('onboarding-continue')).toBeDisabled()
  })

  it('leaves gatewayHealthy false when the probe fails', async () => {
    probe.mockResolvedValue({ isError: true, error: new TypeError('Failed to fetch') })
    const onPersist = vi.fn()
    renderWizard({ initialStep: 'install', initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    await screen.findByTestId('onboarding-install-absent')

    const last = onPersist.mock.calls.at(-1)?.[0] as { state: WizardState }
    expect(last.state.gatewayHealthy).toBe(false)
    expect(screen.getByTestId('onboarding-continue')).toBeDisabled()
  })

  it('patches enrolled only when the registry reports an agent', async () => {
    apiGet.mockResolvedValue({
      data: {
        items: [
          {
            id: 'a1',
            name: 'research-bot',
            framework: 'langgraph',
            version: '0.0.1',
            status: 'active',
            tool_names: [],
            metadata: {},
            session_count: 0,
            policy_violations_count: 0,
            active_sessions: [],
            recent_events: [],
            recent_traces: [],
            last_event: null,
            layer: null,
            pid: null,
          },
        ],
        page: 1,
        per_page: 100,
        total: 1,
      },
      error: undefined,
      response: { ok: true, status: 200 } as Response,
    })
    const onPersist = vi.fn()
    renderWizard({ initialStep: 'enroll', initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    await waitFor(() =>
      expect(onPersist).toHaveBeenLastCalledWith(
        expect.objectContaining({ state: expect.objectContaining({ enrolled: true }) }),
      ),
    )
  })

  it('does not patch enrolled when the registry answers with no agents', async () => {
    const onPersist = vi.fn()
    renderWizard({ initialStep: 'enroll', initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    await screen.findByTestId('onboarding-enroll-empty')
    const last = onPersist.mock.calls.at(-1)?.[0] as { state: WizardState }
    expect(last.state.enrolled).toBe(false)
  })
})
