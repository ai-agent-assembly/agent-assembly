import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { describe, it, expect } from 'vitest'
import { IdentityPage } from './IdentityPage'
import { IAM_TAB_KEYS } from '../features/iam/tabs'

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="location-probe">{location.pathname + location.search}</div>
}

function renderAt(initialEntries: string[]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <Routes>
        <Route path="/identity" element={<IdentityPage />} />
        <Route path="/audit" element={<div data-testid="audit-page">Audit Log</div>} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  )
}

describe('IdentityPage', () => {
  it('renders the four canonical IAM tabs', () => {
    renderAt(['/identity'])
    expect(screen.getByTestId('iam-tabs')).toBeInTheDocument()
    for (const key of IAM_TAB_KEYS) {
      expect(screen.getByTestId(`iam-tab-${key}`)).toBeInTheDocument()
    }
  })

  it('defaults to the members tab when ?tab is absent', () => {
    renderAt(['/identity'])
    expect(screen.getByTestId('iam-tab-members')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('iam-panel-members')).toBeInTheDocument()
  })

  it('falls back to members when ?tab value is unknown', () => {
    renderAt(['/identity?tab=bogus'])
    expect(screen.getByTestId('iam-tab-members')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('iam-panel-members')).toBeInTheDocument()
  })

  it('honours ?tab=services on initial load', () => {
    renderAt(['/identity?tab=services'])
    expect(screen.getByTestId('iam-tab-services')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('iam-panel-services')).toBeInTheDocument()
  })

  it('updates URL ?tab= when a non-default tab is clicked', async () => {
    const user = userEvent.setup()
    renderAt(['/identity'])

    await user.click(screen.getByTestId('iam-tab-roles'))

    expect(screen.getByTestId('iam-tab-roles')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('iam-panel-roles')).toBeInTheDocument()
    expect(screen.getByTestId('location-probe').textContent).toBe('/identity?tab=roles')
  })

  it('clears ?tab= when the default (members) tab is selected', async () => {
    const user = userEvent.setup()
    renderAt(['/identity?tab=services'])

    await user.click(screen.getByTestId('iam-tab-members'))

    expect(screen.getByTestId('location-probe').textContent).toBe('/identity')
  })

  it('exposes a header cross-link to the Audit Log', () => {
    renderAt(['/identity'])
    const link = screen.getByTestId('iam-audit-link')
    expect(link).toHaveAttribute('href', '/audit')
  })
})
