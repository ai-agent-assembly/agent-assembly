import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  extractSandboxInfo,
  isSandboxSummaryEmpty,
  useSandboxSummaryQuery,
  type SandboxSummaryResponse,
} from './api'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

function summary(partial: Partial<SandboxSummaryResponse['counts']> = {}): SandboxSummaryResponse {
  return {
    counts: {
      would_be_denies: 0,
      would_be_redactions: 0,
      would_be_pending_approvals: 0,
      ...partial,
    },
    top_rule: null,
    window_secs: 86_400,
    generated_at: '2026-05-23T14:00:00Z',
  }
}

describe('isSandboxSummaryEmpty', () => {
  it('returns true when every would-be count is zero', () => {
    expect(isSandboxSummaryEmpty(summary())).toBe(true)
  })

  it('returns false when any count is non-zero', () => {
    expect(isSandboxSummaryEmpty(summary({ would_be_denies: 1 }))).toBe(false)
    expect(isSandboxSummaryEmpty(summary({ would_be_redactions: 1 }))).toBe(false)
    expect(isSandboxSummaryEmpty(summary({ would_be_pending_approvals: 1 }))).toBe(false)
  })
})

describe('extractSandboxInfo', () => {
  it('returns dryRun=true and the shadow decision when payload carries them', () => {
    const info = extractSandboxInfo('{"dry_run":true,"shadow_decision":"deny"}')
    expect(info.dryRun).toBe(true)
    expect(info.shadowDecision).toBe('deny')
  })

  it('returns dryRun=false when the payload omits dry_run', () => {
    const info = extractSandboxInfo('{"decision":"Allow"}')
    expect(info.dryRun).toBe(false)
    expect(info.shadowDecision).toBeNull()
  })

  it('treats dry_run=false explicitly as live enforcement', () => {
    const info = extractSandboxInfo('{"dry_run":false}')
    expect(info.dryRun).toBe(false)
  })

  it('falls back to dryRun=false for malformed JSON', () => {
    expect(extractSandboxInfo('not-json').dryRun).toBe(false)
  })

  it('treats empty-string shadow_decision as null', () => {
    expect(extractSandboxInfo('{"dry_run":true,"shadow_decision":""}').shadowDecision).toBeNull()
  })
})

describe('useSandboxSummaryQuery', () => {
  let get: Mock
  beforeEach(() => {
    get = vi.spyOn(api, 'GET') as unknown as Mock
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('defaults to the 24h window and omits root when unset', async () => {
    get.mockResolvedValue({ data: summary() } satisfies FetchResult)
    const { result } = renderHook(() => useSandboxSummaryQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/audit/sandbox-summary', {
      params: { query: { window: '24h' } },
    })
  })

  it('forwards an explicit window and root in the query', async () => {
    get.mockResolvedValue({ data: summary() } satisfies FetchResult)
    const { result } = renderHook(
      () => useSandboxSummaryQuery({ window: '7d', root: 'agent-root' }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/audit/sandbox-summary', {
      params: { query: { window: '7d', root: 'agent-root' } },
    })
  })

  it('throws when the gateway returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useSandboxSummaryQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch sandbox summary')
  })

  it('throws when the response body is empty', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useSandboxSummaryQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Sandbox summary response was empty')
  })
})
