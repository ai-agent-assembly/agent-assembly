import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { BurnCallouts } from './BurnCallouts'

describe('BurnCallouts', () => {
  it('renders nothing below the 80% warning band', () => {
    const { container } = render(<BurnCallouts dailyPct={40} dailyLimit={200} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing when no daily limit is configured', () => {
    const { container } = render(<BurnCallouts dailyPct={null} dailyLimit={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the amber warning between 80% and 95%', () => {
    render(<BurnCallouts dailyPct={85} dailyLimit={200} />)
    const warn = screen.getByTestId('costs-callout-warn')
    expect(warn).toHaveTextContent('Daily budget warning — 85.0%')
    expect(warn).toHaveTextContent('$200.00')
    expect(screen.queryByTestId('costs-callout-danger')).not.toBeInTheDocument()
  })

  it('shows the red critical banner at or above 95%', () => {
    render(<BurnCallouts dailyPct={105} dailyLimit={200} />)
    const danger = screen.getByTestId('costs-callout-danger')
    expect(danger).toHaveTextContent('Daily budget critical — 105.0%')
    expect(screen.queryByTestId('costs-callout-warn')).not.toBeInTheDocument()
  })
})
