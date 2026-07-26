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

/**
 * Destinations for the two secondary actions, whose labels come from the shared
 * copy tables and name an external destination (AAASM-5168).
 *
 * These used to be in-app routes: "Open status page" navigated to `/audit` and
 * "View install docs" to `/agents`, so a new operator on an empty install
 * clicked through to an empty Fleet table. The copy tables are shared with
 * every other page, so the fix belongs here in the handlers rather than in the
 * labels. The status host is the one `ErrorState`'s own message tells the
 * operator to check; the docs host matches the quickstart link Fleet already
 * ships.
 */
const STATUS_PAGE_URL = 'https://status.agent-assembly.com'
const INSTALL_DOCS_URL = 'https://docs.agent-assembly.com/quickstart'

/** `noopener` keeps the opened tab from reaching back through `window.opener`. */
function openExternal(url: string): void {
  window.open(url, '_blank', 'noopener,noreferrer')
}

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
        onSecondary={() => openExternal(STATUS_PAGE_URL)}
      />
    )
  }
  if (args.isEmpty) {
    return (
      <EmptyState
        page="overview"
        onCta={() => args.navigate('/onboarding')}
        onSecondary={() => openExternal(INSTALL_DOCS_URL)}
      />
    )
  }
  return null
}
