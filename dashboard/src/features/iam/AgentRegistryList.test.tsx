/**
 * Tone-lookup guard for AAASM-5230.
 *
 * The status tone was resolved through a plain object literal keyed by a
 * wire-derived value: `STATUS_CLASS[agentStatusVariant(status)]`. Because the
 * gateway emits the status verbatim, a status whose outer variant happens to
 * name an inherited `Object.prototype` member (`constructor`, `toString`,
 * `valueOf`, `__proto__`, `hasOwnProperty`) resolved to that inherited member
 * instead of `undefined`, so the `?? 'iam-agent-status--other'` fallback was
 * dead for those names. A `Map.get()` returns `undefined` for non-own keys,
 * which restores the fallback. These tests render the list and assert the tone
 * class on the status chip, so they fail against the object-literal version.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { AgentRegistryList } from './AgentRegistryList'
import { api } from '../../api/client'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function renderList() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <AgentRegistryList selectedAgentId={null} onSelect={() => {}} />
    </QueryClientProvider>,
  )
}

function rawAgent(id: string, status: string) {
  return {
    id,
    name: `agent-${id}`,
    framework: 'langgraph',
    version: '1.0.0',
    status,
    tool_names: [],
    metadata: {},
    session_count: 0,
    policy_violations_count: 0,
    active_sessions: [],
    recent_events: [],
    recent_traces: [],
    last_event: '2026-07-26T09:00:00Z',
  }
}

let get: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

/** Read the status chip's className for a given agent row. */
async function statusChipClass(agentId: string): Promise<string> {
  const chip = await screen.findByTestId(`agent-status-${agentId}`)
  // TruthfulValue renders the status chip span inside the cell.
  const span = chip.querySelector('.iam-agent-status')
  if (!span) throw new Error(`no status chip rendered for ${agentId}`)
  return span.className
}

describe('AgentRegistryList status tone', () => {
  it('maps the three real registry variants to their own tone', async () => {
    get.mockResolvedValue({
      data: {
        items: [
          rawAgent('active', 'Active'),
          rawAgent('suspended', 'Suspended(Manual)'),
          rawAgent('deregistered', 'Deregistered'),
        ],
        page: 1,
        per_page: 100,
        total: 3,
      },
    } satisfies FetchResult)

    renderList()
    await waitFor(() => expect(get).toHaveBeenCalled())

    expect(await statusChipClass('active')).toContain('iam-agent-status--active')
    expect(await statusChipClass('suspended')).toContain('iam-agent-status--suspended')
    expect(await statusChipClass('deregistered')).toContain('iam-agent-status--deregistered')
  })

  // Each of these is an inherited `Object.prototype` member. Keyed into a plain
  // object literal it resolves to the inherited value (a function or the
  // prototype), so the `?? '--other'` fallback never fired and the chip
  // borrowed a non-string tone. `Map.get()` returns `undefined` for them.
  it.each(['constructor', 'toString', 'valueOf', '__proto__', 'hasOwnProperty'])(
    'falls a %s status through to the --other tone, never an inherited member',
    async (inheritedName) => {
      get.mockResolvedValue({
        data: {
          items: [rawAgent('inherited', inheritedName)],
          page: 1,
          per_page: 100,
          total: 1,
        },
      } satisfies FetchResult)

      renderList()
      await waitFor(() => expect(get).toHaveBeenCalled())

      const className = await statusChipClass('inherited')
      // The only tone applied is the neutral fallback.
      expect(className).toContain('iam-agent-status--other')
      expect(className).not.toContain('iam-agent-status--active')
      expect(className).not.toContain('iam-agent-status--suspended')
      expect(className).not.toContain('iam-agent-status--deregistered')
      // No inherited member ever leaks in as a tone class (e.g. `[object ...]`
      // or a stringified function).
      expect(className).not.toMatch(/function|\[object/i)
    },
  )
})
