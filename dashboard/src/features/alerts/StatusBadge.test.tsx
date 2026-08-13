import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { StatusBadge } from './StatusBadge'
import type { AlertStatus } from './types'

// AAASM-5217: `status` reaches this component from the single-alert-detail
// path (`useAlertQuery` in `api.ts`) through a bare `as T` cast with no
// canonicalisation. `STATUS_STYLE[status]` on an unrecognised or
// prototype-inherited key would previously throw on destructuring
// `undefined`, crashing the whole alert detail drawer instead of rendering a
// badge.
describe('StatusBadge', () => {
  it.each(['FIRING', 'RESOLVED', 'SUPPRESSED'] as const)('renders the %s badge', (status) => {
    render(<StatusBadge status={status} />)
    expect(screen.getByTestId(`status-badge-${status}`)).toHaveTextContent(status)
  })

  it.each([
    ['a plain unknown status', 'ARCHIVED'],
    ['the inherited "__proto__" key', '__proto__'],
    ['the inherited "constructor" key', 'constructor'],
  ])('renders %s as the unknown badge instead of throwing', (_label, value) => {
    expect(() =>
      render(<StatusBadge status={value as unknown as AlertStatus} />),
    ).not.toThrow()
    const badge = screen.getByTestId('status-badge-unknown')
    expect(badge).toHaveTextContent(value)
  })
})
