import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
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
  observation_profile: 'standard',
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

    // AAASM-6197: awaited through `waitFor` rather than read once. This line is
    // the one that actually flaked, twice, in unrelated pull requests:
    // `AssertionError: expected true to be false`, 1 failed of 3601.
    //
    // The transcript and the snapshot are two different observables. `setResult`
    // drives the DOM inside the commit; `onPersist` fires from a passive effect
    // that React flushes later, so a single read can land on the *previous*
    // snapshot — here the healthy probe's `true`, exactly the value this test
    // denies. The reason that is rare rather than constant is that Testing
    // Library's async helpers are `act`-wrapped and normally drain that effect
    // before the `await` resolves: instrumented locally, the snapshot was
    // already fresh in 300 of 300 runs. So the race is narrow and cannot be
    // reproduced on demand here — `waitFor` removes the dependence on that
    // drain happening rather than papering over a measured ordering.
    await waitFor(() => {
      const last = onPersist.mock.calls.at(-1)?.[0] as { state: WizardState }
      expect(last.state.gatewayHealthy).toBe(false)
    })
    expect(screen.getByTestId('onboarding-continue')).toBeDisabled()
  })

  it('leaves gatewayHealthy false when the probe fails', async () => {
    probe.mockResolvedValue({ isError: true, error: new TypeError('Failed to fetch') })
    const onPersist = vi.fn()
    renderWizard({ initialStep: 'install', initialState: EMPTY_STATE, onPersist })

    fireEvent.click(screen.getByTestId('onboarding-install-verify'))
    await screen.findByTestId('onboarding-install-absent')

    // AAASM-6197: the call count is asserted first, and it is load-bearing —
    // demonstrated by mutation rather than argued. `EMPTY_STATE.gatewayHealthy`
    // is already `false`, so the value assertion alone is satisfied by the
    // *mount* snapshot whether or not the probe ever reported anything. Reduce
    // `Step2InstallSdk`'s `onProbed` to report only success — a plausible
    // one-directional-reporting regression — and the value-only form passed in
    // 0 of 15 runs' worth of detection, while this form failed in 15 of 15.
    //
    // `patchState` returns `{ ...prev, ...patch }`, a fresh object, so a failing
    // probe emits a second snapshot even though the value is unchanged;
    // requiring one is what makes this assert the probe's finding. Note this is
    // an anti-vacuity guard, not a flake fix: on the unmutated path the count is
    // already 2 at the read point in 300 of 300 runs.
    await waitFor(() => {
      expect(onPersist.mock.calls.length).toBeGreaterThan(1)
      const last = onPersist.mock.calls.at(-1)?.[0] as { state: WizardState }
      expect(last.state.gatewayHealthy).toBe(false)
    })
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
            is_flagged: false,            active_sessions: [],
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
    // AAASM-6197: this test's name asserts an *absence*, so it asserts one
    // rather than re-reading a field `EMPTY_STATE` already sets to `false`. On
    // the clean path the last snapshot is the mount snapshot in 300 of 300 runs
    // measured, so the old form was reading the initial state, not a finding.
    //
    // Stated honestly: this is a clarity and ordering change, not a demonstrated
    // detection gain. Two mutations that wrongly patch `enrolled` on the empty
    // path — `hasAgents` accepting a known zero, and dropping the `hasAgents`
    // guard on the reporting effect — are caught by either form, 10 of 10 runs
    // each. No regression was found that the old assertion misses.
    //
    // The flush is not a sleep. A wrong patch would reach `onPersist` from the
    // passive effect belonging to the commit that rendered the node awaited
    // above, and `act` drains exactly those, so the absence is asserted after
    // the only point at which it could have been violated.
    await act(async () => {})
    expect(onPersist).not.toHaveBeenCalledWith(
      expect.objectContaining({ state: expect.objectContaining({ enrolled: true }) }),
    )
  })
})
