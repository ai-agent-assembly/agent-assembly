import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, beforeEach } from 'vitest'
import { OnboardingPage } from '../../../pages/OnboardingPage'
import { ToastProvider } from '../../../components/ToastProvider'
import { ONBOARDING_COMPLETED_KEY } from '../useGatewayConfiguredGuard'
import {
  ONBOARDING_SESSION_KEY,
  saveWizardSession,
} from '../useWizardSession'
import { EMPTY_STATE } from '../types'

function renderAt(path: string) {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/" element={<div data-testid="root-page">root</div>} />
          <Route path="/onboarding" element={<OnboardingPage />} />
        </Routes>
      </MemoryRouter>
    </ToastProvider>,
  )
}

describe('OnboardingPage', () => {
  beforeEach(() => {
    window.localStorage.removeItem(ONBOARDING_COMPLETED_KEY)
    window.localStorage.removeItem(ONBOARDING_SESSION_KEY)
  })

  it('renders the wizard when gateway is not yet configured', () => {
    renderAt('/onboarding')
    expect(screen.getByTestId('onboarding-wizard')).toBeInTheDocument()
  })

  it('redirects to / immediately when gateway is already configured', () => {
    window.localStorage.setItem(ONBOARDING_COMPLETED_KEY, 'true')
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
        installVerified: true,
        identity: {
          did: 'did:aa:abc',
          alg: 'Ed25519',
          fingerprint: 'AA:BB',
          issuedAt: 'x',
        },
      },
    })
    renderAt('/onboarding')
    expect(screen.getByTestId('onboarding-step-counter')).toHaveTextContent(
      'step 4 of 5',
    )
    expect(screen.getByTestId('onboarding-step-policy')).toBeInTheDocument()
  })

  it('clears the persisted session and fires a success toast on "skip onboarding"', () => {
    renderAt('/onboarding')
    // The wizard mounts and immediately persists its initial snapshot,
    // so the session key is present.
    expect(window.localStorage.getItem(ONBOARDING_SESSION_KEY)).not.toBe(null)
    fireEvent.click(screen.getByTestId('onboarding-skip-all'))
    expect(window.localStorage.getItem(ONBOARDING_COMPLETED_KEY)).toBe('true')
    expect(window.localStorage.getItem(ONBOARDING_SESSION_KEY)).toBe(null)
    expect(screen.getByTestId('root-page')).toBeInTheDocument()
    expect(screen.getByTestId('toast-container')).toHaveTextContent(/Onboarding skipped/i)
  })

  it('fires a success toast and clears the session when wizard is finished', () => {
    saveWizardSession({
      step: 'enroll',
      state: {
        framework: 'langchain',
        installVerified: true,
        identity: {
          did: 'did:aa:abc',
          alg: 'Ed25519',
          fingerprint: 'AA:BB',
          issuedAt: 'x',
        },
        policyPreset: 'read-only',
        enrolled: true,
      },
    })
    renderAt('/onboarding')
    fireEvent.click(screen.getByTestId('onboarding-continue'))
    expect(window.localStorage.getItem(ONBOARDING_COMPLETED_KEY)).toBe('true')
    expect(window.localStorage.getItem(ONBOARDING_SESSION_KEY)).toBe(null)
    expect(screen.getByTestId('toast-container')).toHaveTextContent(/Setup complete/i)
  })
})
