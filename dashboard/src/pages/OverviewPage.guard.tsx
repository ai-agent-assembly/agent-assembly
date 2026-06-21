import type { ReactElement } from 'react'
import { useNavigate } from 'react-router-dom'
import { LoadingState } from '../components/LoadingState'
import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { ignorePromise } from '../lib/ignorePromise'

/**
 * Loading / error / empty guard for the Overview page. Lives in its own module
 * so `OverviewPage` stays under SonarCloud's cognitive-complexity budget
 * (S3776) and so each branch is unit-testable without rendering the whole page.
 * PascalCase name + `ReactElement | null` return keep this a components-only
 * module (react-refresh `only-export-components`).
 */
export function OverviewGuard(
  args: Readonly<{
    isLoading: boolean
    isError: boolean
    isEmpty: boolean
    navigate: ReturnType<typeof useNavigate>
    refetch: () => Promise<unknown>
  }>,
): ReactElement | null {
  if (args.isLoading) return <LoadingState page="overview" />
  if (args.isError) {
    return (
      <ErrorState
        kind="generic"
        onRetry={() => ignorePromise(args.refetch())}
        onSecondary={() => args.navigate('/audit')}
      />
    )
  }
  if (args.isEmpty) {
    return (
      <EmptyState
        page="overview"
        onCta={() => args.navigate('/onboarding')}
        onSecondary={() => args.navigate('/agents')}
      />
    )
  }
  return null
}
