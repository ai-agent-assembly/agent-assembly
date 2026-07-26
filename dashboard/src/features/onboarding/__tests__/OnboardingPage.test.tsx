import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { OnboardingPage } from '../../../pages/OnboardingPage'
import { ToastProvider } from '../../../components/ToastProvider'
import { ONBOARDING_COMPLETED_KEY } from '../useGatewayConfiguredGuard'
import {
  ONBOARDING_SESSION_KEY,
  saveWizardSession,
} from '../useWizardSession'
import { EMPTY_STATE } from '../types'

// The enroll step polls the agent registry; see `features/onboarding/api.test.tsx`
// for why the client, not `globalThis.fetch`, is the mock boundary.
vi.mock('../../../api/client', () => ({
  api: {
    GET: vi.fn().mockResolvedValue({
      data: { items: [], page: 1, per_page: 100, total: 0 },
      error: undefined,
      response: { ok: true, status: 200 },
    }),
  },
}))

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/" element={<div data-testid="root-page">root</div>} />
            <Route path="/onboarding" element={<OnboardingPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('OnboardingPage', () => {
  beforeEach(() => {
    globalThis.localStorage.removeItem(ONBOARDING_COMPLETED_KEY)
    globalThis.localStorage.removeItem(ONBOARDING_SESSION_KEY)
  })

  it('renders the wizard when gateway is not yet configured', () => {
    renderAt('/onboarding')
    expect(screen.getByTestId('onboarding-wizard')).toBeInTheDocument()
  })

  it('redirects to / immediately when gateway is already configured', () => {
    globalThis.localStorage.setItem(ONBOARDING_COMPLETED_KEY, 'true')
    renderAt('/onboarding')
    expect(screen.queryByTestId('onboarding-wizard')).toBeNull()
    expect(screen.getByTestId('root-page')).toBeInTheDocument()
  })

  it('hydrates the wizard at the persisted step when a session exists', () => {
    saveWizardSession({
      step: 'policy',
      state: {
        ...EMPTY_STATE,
        framework: 'langchain',
        gatewayHealthy: true,
      },
    })
    renderAt('/onboarding')
    expect(screen.getByTestId('onboarding-step-counter')).toHaveTextContent(
      'step 4 of 5',
    )
    expect(screen.getByTestId('onboarding-step-policy')).toBeInTheDocument()
  })

  it('tells the operator when saved progress was discarded rather than restarting silently', () => {
    globalThis.localStorage.setItem(
      ONBOARDING_SESSION_KEY,
      // A pre-AAASM-5179 payload: carries the withdrawn `identity` key.
      JSON.stringify({
        step: 'policy',
        state: {
          framework: 'langchain',
          installVerified: true,
          identity: { did: 'did:aa:abc' },
          policyPreset: 'read-only',
          enrolled: false,
        },
      }),
    )
    renderAt('/onboarding')

    expect(screen.getByTestId('onboarding-step-counter')).toHaveTextContent('step 1 of 5')
    expect(screen.getByTestId('toast-container')).toHaveTextContent(/discarded/i)
  })

  it('says nothing when there was no session to discard', () => {
    renderAt('/onboarding')
    expect(screen.getByTestId('toast-container')).not.toHaveTextContent(/discarded/i)
  })

  it('clears the persisted session and fires a success toast on "skip onboarding"', () => {
    renderAt('/onboarding')
    // The wizard mounts and immediately persists its initial snapshot,
    // so the session key is present.
    expect(globalThis.localStorage.getItem(ONBOARDING_SESSION_KEY)).not.toBeNull()
    fireEvent.click(screen.getByTestId('onboarding-skip-all'))
    expect(globalThis.localStorage.getItem(ONBOARDING_COMPLETED_KEY)).toBe('true')
    expect(globalThis.localStorage.getItem(ONBOARDING_SESSION_KEY)).toBeNull()
    expect(screen.getByTestId('root-page')).toBeInTheDocument()
    expect(screen.getByTestId('toast-container')).toHaveTextContent(/Onboarding skipped/i)
  })

  it('fires a success toast and clears the session when wizard is finished', () => {
    saveWizardSession({
      step: 'enroll',
      state: {
        framework: 'langchain',
        gatewayHealthy: true,
        policyPreset: 'read-only',
        enrolled: true,
      },
    })
    renderAt('/onboarding')
    fireEvent.click(screen.getByTestId('onboarding-continue'))
    expect(globalThis.localStorage.getItem(ONBOARDING_COMPLETED_KEY)).toBe('true')
    expect(globalThis.localStorage.getItem(ONBOARDING_SESSION_KEY)).toBeNull()
    expect(screen.getByTestId('toast-container')).toHaveTextContent(/Setup complete/i)
  })
})
