import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type SandboxSummaryResponse = components['schemas']['SandboxSummaryResponse']
export type SandboxSummaryCounts = components['schemas']['SandboxSummaryCounts']
export type SandboxSummaryTopRule = components['schemas']['SandboxSummaryTopRule']

export type SandboxWindow = '1h' | '24h' | '7d' | '30d'

interface UseSandboxSummaryQueryOptions {
  window?: SandboxWindow
  root?: string
}

/**
 * Fetches the global observe-mode aggregate from
 * `GET /api/v1/audit/sandbox-summary` (AAASM-1911 / aa-api PR #767).
 *
 * Returns the would-be deny / redaction / pending-approval counts plus the
 * most-frequently matched policy rule across all `dry_run: true` audit
 * entries in the window. The endpoint is global today; per-policy scoping
 * would need a follow-up `policy` query parameter on the API.
 */
export function useSandboxSummaryQuery(options: UseSandboxSummaryQueryOptions = {}) {
  const window_ = options.window ?? '24h'
  const root = options.root ?? undefined
  return useQuery<SandboxSummaryResponse>({
    queryKey: ['audit', 'sandbox-summary', window_, root ?? null],
    queryFn: async () => {
      const query: { window?: string; root?: string } = { window: window_ }
      if (root) query.root = root
      const { data, error } = await api.GET('/api/v1/audit/sandbox-summary', {
        params: { query },
      })
      if (error) throw new Error('Failed to fetch sandbox summary')
      if (!data) throw new Error('Sandbox summary response was empty')
      return data
    },
  })
}

/**
 * True when every count in the summary is zero. Callers use this to hide
 * the SandboxSummaryCard banner when there's no observe-mode activity to
 * surface.
 */
export function isSandboxSummaryEmpty(summary: SandboxSummaryResponse): boolean {
  const c = summary.counts
  return c.would_be_denies === 0 && c.would_be_redactions === 0 && c.would_be_pending_approvals === 0
}
