import type { ReactNode } from 'react'
import { StatusState } from '../truthfulness'

interface EmptyStateProps {
  title: string
  description?: ReactNode
  action?: ReactNode
  icon?: ReactNode
}

/**
 * A genuinely empty result — the query succeeded and returned zero rows.
 *
 * Converged onto `StatusState` under AAASM-5173. Props and the `empty-state`
 * test id are unchanged, so every existing call site keeps working, but the
 * markup, roles, and tone now come from the one shared implementation rather
 * than a second, divergent one.
 *
 * @deprecated for new surfaces — use `StatusState` directly, which can also say
 * *why* a value is missing (`unknown` / `unavailable` / `unconfigured` /
 * `not-evaluated` / `not-supported` / `demo`). This wrapper can only say
 * "empty", and "empty" is precisely the answer that must not be reached for by
 * default: a failed or unevaluated surface is not an empty one.
 */
export function EmptyState({ title, description, action, icon }: Readonly<EmptyStateProps>) {
  return (
    <StatusState
      state={null}
      title={title}
      description={description}
      icon={icon}
      action={action}
      testId="empty-state"
    />
  )
}
