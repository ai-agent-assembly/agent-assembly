import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, it, expect, beforeEach } from 'vitest'
import { OnboardingPage } from '../../../pages/OnboardingPage'
import { ONBOARDING_COMPLETED_KEY } from '../useGatewayConfiguredGuard'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/" element={<div data-testid="root-page">root</div>} />
        <Route path="/onboarding" element={<OnboardingPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('OnboardingPage', () => {
  beforeEach(() => {
    window.localStorage.removeItem(ONBOARDING_COMPLETED_KEY)
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

  it('marks gateway configured and redirects when "skip onboarding" is clicked', () => {
    renderAt('/onboarding')
    fireEvent.click(screen.getByTestId('onboarding-skip-all'))
    expect(window.localStorage.getItem(ONBOARDING_COMPLETED_KEY)).toBe('true')
    expect(screen.getByTestId('root-page')).toBeInTheDocument()
  })
})
