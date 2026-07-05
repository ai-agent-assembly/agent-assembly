import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AnalyticsPage } from './AnalyticsPage'
import { ANALYTICS_BACKEND_AVAILABLE } from '../features/analytics/analyticsBackend'

// The analytics dashboard is entirely backed by the /api/v1/analytics/*
// endpoints, which do not exist in aa-api yet (AAASM-4138). Until they ship the
// flag stays off and the page must degrade to the shared "coming soon"
// placeholder rather than mount panels that would all fail their fetches.
describe('AnalyticsPage', () => {
  it('is gated off until the analytics backend exists', () => {
    expect(ANALYTICS_BACKEND_AVAILABLE).toBe(false)
  })

  it('renders the coming-soon placeholder while the backend is unavailable', () => {
    render(
      <MemoryRouter initialEntries={['/analytics']}>
        <AnalyticsPage />
      </MemoryRouter>,
    )

    const placeholder = screen.getByTestId('coming-soon')
    expect(placeholder).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Analytics' })).toBeInTheDocument()
    // None of the analytics data panels should mount while gated.
    expect(screen.queryByTestId('cost-breakdown-panel')).not.toBeInTheDocument()
  })
})
