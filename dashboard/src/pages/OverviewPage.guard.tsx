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
 * Destination for "View install docs" (AAASM-5168).
 *
 * The label comes from the shared `EmptyState` copy table, which every other
 * page depends on, so the fix belongs in this handler rather than in the label.
 * It used to navigate in-app to `/agents`, landing a brand-new operator on an
 * empty Fleet table.
 *
 * This URL is verified to resolve: `docs.agent-assembly.com/core/` returns 200.
 * The obvious-looking `/quickstart` — which `FleetPage` still links to — is a
 * **404**, so it was not copied here. Re-point this only at a path confirmed
 * with a real request; ADR 0007's table lists the docs host itself as "Future
 * (placeholder)" and is stale on that point, which makes the table an unsafe
 * substitute for probing.
 */
const INSTALL_DOCS_URL = 'https://docs.agent-assembly.com/core/'

/**
 * Why the error state's secondary action opens nothing.
 *
 * `ErrorState`'s copy labels this button "Open status page", but no status page
 * exists: `status.agent-assembly.com` returns **HTTP 530** and ADR 0007 marks
 * it "Future (placeholder)". Linking to it would put a Cloudflare error behind
 * the one button a human clicks *during an outage* — a worse failure than the
 * `/audit` misroute this ticket replaced, not a better one.
 *
 * Nor can the affordance simply be removed from here: `ErrorState` renders the
 * button from its copy table, not from the presence of a handler, so omitting
 * `onSecondary` yields a silently inert button. Until the shared component
 * grows a way to suppress a secondary action — which is outside this page's
 * ownership — the honest behaviour is to say so rather than to navigate
 * somewhere that cannot help.
 */
const NO_STATUS_PAGE_MESSAGE =
  'No status page is available yet. Retry, or check the gateway logs directly.'

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
    /**
     * Passed in rather than read from context here, matching `navigate` — this
     * module is invoked as a plain function from `OverviewPage`'s body, so it
     * must not call hooks of its own.
     */
    toast: (message: string) => void
  }>,
): ReactElement | null {
  if (args.isLoading) return <LoadingState page="overview" />
  if (args.isError) {
    return (
      <ErrorState
        kind="generic"
        onRetry={() => ignorePromise(args.refetch())}
        onSecondary={() => args.toast(NO_STATUS_PAGE_MESSAGE)}
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
