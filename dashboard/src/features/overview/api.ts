import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type EnforcementTimeline = components['schemas']['EnforcementTimelineResponse']
export type EnforcementBucket = components['schemas']['EnforcementBucket']

/**
 * Windowed enforcement decision counts (allow/narrow/deny/scrub) for the
 * Overview posture timeline. The `window` is part of the query key so switching
 * the header window preset refetches rather than serving a stale window.
 */
export function useEnforcementTimelineQuery(window: string) {
  return useQuery<EnforcementTimeline>({
    queryKey: ['overview', 'enforcement-timeline', window],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/overview/enforcement-timeline', {
        params: { query: { window } },
      })
      if (error) throw new Error('Failed to fetch enforcement timeline')
      if (!data) throw new Error('Enforcement timeline response was empty')
      return data
    },
  })
}
