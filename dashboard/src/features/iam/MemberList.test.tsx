import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { RoleBadge } from './MemberList'

const DEFAULT_TONE = 'iam-role-badge--viewer'

function toneClass(role: string): string {
  render(<RoleBadge role={role} />)
  // The badge span carries the base class plus exactly one tone class.
  const badge = screen.getByText(role)
  const tone = [...badge.classList].find((c) => c !== 'iam-role-badge')
  return tone ?? ''
}

describe('MemberList RoleBadge tone', () => {
  it.each([
    ['org_admin', 'iam-role-badge--owner'],
    ['team_admin', 'iam-role-badge--admin'],
    ['developer', 'iam-role-badge--member'],
    ['viewer', 'iam-role-badge--viewer'],
    ['auditor', 'iam-role-badge--viewer'],
  ])('maps the real role %s to its tone class', (role, expected) => {
    expect(toneClass(role)).toBe(expected)
  })

  // Load-bearing: an object literal indexed as ROLE_BADGE_TONE[role] resolves
  // inherited Object.prototype keys, so a crafted role id like `constructor`
  // reaches a prototype method's class name instead of falling to the default
  // tone. A Map `.get()` returns undefined for these names, so they hit the
  // default. Against the pre-fix object literal these cases fail.
  it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf'])(
    'falls back to the default tone for the inherited key %s',
    (role) => {
      expect(toneClass(role)).toBe(DEFAULT_TONE)
    },
  )

  it('falls back to the default tone for any unknown role', () => {
    expect(toneClass('not-a-role')).toBe(DEFAULT_TONE)
  })
})
