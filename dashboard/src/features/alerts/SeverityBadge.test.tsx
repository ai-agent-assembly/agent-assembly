import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SeverityBadge } from './SeverityBadge'
import type { Severity } from './types'

// AAASM-5217: `severity` reaches this component from the single-alert-detail
// path (`useAlertQuery` in `api.ts`) through a bare `as T` cast with no
// canonicalisation, unlike the `/alerts` list path's `canonicalSeverity`. A
// hostile or malformed value must not resolve `SEVERITY_BG[severity]` to
// `undefined` (a silently blank badge) or an inherited `Object.prototype`
// member.
describe('SeverityBadge', () => {
  it.each(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)('renders the %s badge', (severity) => {
    render(<SeverityBadge severity={severity} />)
    expect(screen.getByTestId(`severity-badge-${severity}`)).toHaveTextContent(severity)
  })

  it.each([
    ['a plain unknown severity', 'EXTREME'],
    ['the inherited "__proto__" key', '__proto__'],
    ['the inherited "constructor" key', 'constructor'],
  ])('renders %s as the unknown badge with a real background, not undefined', (_label, value) => {
    render(<SeverityBadge severity={value as unknown as Severity} />)
    const badge = screen.getByTestId('severity-badge-unknown')
    expect(badge).toHaveTextContent(value)
    expect(badge.style.background).not.toBe('')
  })
})
