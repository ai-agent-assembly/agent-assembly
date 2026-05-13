import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusChip } from './StatusChip'
import { ModeChip } from './ModeChip'
import { TrustBar } from './TrustBar'

describe('StatusChip', () => {
  it.each(['active', 'idle', 'suspended', 'error'] as const)(
    'applies the matching modifier for status %s',
    (status) => {
      render(<StatusChip status={status} />)
      const chip = screen.getByTestId('fleet-status')
      expect(chip).toHaveClass('fleet-status', `fleet-status--${status}`)
      expect(chip.textContent).toContain(status)
    },
  )

  it('falls back to the unknown modifier for unrecognised statuses', () => {
    render(<StatusChip status="deregistered" />)
    const chip = screen.getByTestId('fleet-status')
    expect(chip).toHaveClass('fleet-status--unknown')
    expect(chip.textContent).toContain('deregistered')
  })
})

describe('ModeChip', () => {
  it.each(['enforce', 'shadow', 'off'] as const)('applies the matching modifier for %s mode', (mode) => {
    render(<ModeChip mode={mode} />)
    const chip = screen.getByTestId('fleet-mode')
    expect(chip).toHaveClass('fleet-mode', `fleet-mode--${mode}`)
    expect(chip.textContent?.toLowerCase()).toContain(mode)
  })
})

describe('TrustBar', () => {
  it('renders an em-dash when the score is null', () => {
    render(<TrustBar score={null} />)
    const bar = screen.getByTestId('fleet-trust')
    expect(bar).toHaveClass('fleet-trust--empty')
    expect(bar.textContent).toBe('—')
  })

  it.each([
    [95, 'fleet-trust--ok'],
    [80, 'fleet-trust--ok'],
    [75, 'fleet-trust--warn'],
    [60, 'fleet-trust--warn'],
    [42, 'fleet-trust--danger'],
    [0, 'fleet-trust--danger'],
  ])('applies the matching band for score %s → %s', (score, expectedClass) => {
    render(<TrustBar score={score} />)
    const bar = screen.getByTestId('fleet-trust')
    expect(bar).toHaveClass(expectedClass)
    expect(bar.textContent).toContain(String(score))
  })

  it('clamps the rendered width into 0–100', () => {
    render(<TrustBar score={150} />)
    const fill = document.querySelector('.fleet-trust__fill') as HTMLElement | null
    expect(fill?.style.width).toBe('100%')
  })
})
