import type { Decorator } from '@storybook/react'
import type { Scope } from '../src/auth/AuthContext'
import { GrantScopes } from '../src/auth/GrantScopes'
import { WRITE_SCOPES } from '../src/auth/testScopes'

/**
 * The caller every story runs as unless it says otherwise.
 *
 * Deliberately *not* every scope. `usePermissions` fails closed with no
 * provider (AAASM-5180), and the obvious repair — grant admin globally — would
 * rebuild that deleted permissive default inside Storybook: every gated control
 * enabled everywhere, so the read-only rendering (disabled states, the
 * write-required hint) would never be seen by the designers and QA reviewers
 * Storybook exists for, and a story could claim nothing about permissions while
 * still looking correct. A plain write-capable operator is the view most
 * stories are actually illustrating; admin-only surfaces opt in explicitly.
 */
const DEFAULT_STORY_SCOPES: readonly Scope[] = WRITE_SCOPES

/**
 * Mount an `AuthContext` around every story, mirroring what the test suite does
 * via `GrantScopes` (AAASM-5188).
 *
 * Global rather than per-story so a new story rendering a gated control is
 * usable the moment it is written, instead of silently rendering a dead,
 * permanently-disabled control until someone notices.
 *
 * A story overrides the caller with `parameters: { scopes: [...] }` — that is
 * how a permission state becomes a *reviewable* story (a read-only variant next
 * to the write-capable one) rather than something only the test suite ever
 * sees.
 */
export const withScopes: Decorator = (Story, context) => {
  const scopes = (context.parameters.scopes as Scope[] | undefined) ?? DEFAULT_STORY_SCOPES
  return (
    <GrantScopes scopes={[...scopes]}>
      <Story />
    </GrantScopes>
  )
}
