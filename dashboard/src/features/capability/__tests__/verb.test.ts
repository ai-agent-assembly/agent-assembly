import { describe, expect, it } from 'vitest'
import { defaultVerb } from '../verb'
import type { CapabilityAgent, CapCell, Resource, Verb } from '../types'

/**
 * The three system resource families `project_matrix` always emits, plus one
 * MCP tool column — the shape `GET /capability/matrix` actually returns
 * (`aa-api/src/routes/capability.rs:497-524`, `:626-641`).
 */
const RESOURCES: Resource[] = [
  { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
  { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
  { id: 'network-outbound', name: 'Network', group: 'infra', paths: [] },
  { id: 'search_web', name: 'search_web', paths: [] },
]

function cell(overrides: Partial<CapCell>): CapCell {
  return { read: 'na', write: 'na', delete: 'na', exec: 'na', ...overrides }
}

function agent(id: string, caps: Record<string, CapCell>): CapabilityAgent {
  return {
    id,
    name: id,
    framework: 'langgraph',
    trust: null,
    status: 'active',
    lastSeen: '2026-07-26T00:00:00Z',
    caps,
  }
}

/** An agent as the live projection actually shapes it. */
function projectedAgent(id: string): CapabilityAgent {
  return agent(id, {
    filesystem: cell({ read: 'allow', write: 'allow', delete: 'deny' }),
    terminal: cell({ exec: 'allow' }),
    'network-outbound': cell({ exec: 'deny' }),
    search_web: cell({ exec: 'allow' }),
  })
}

describe('defaultVerb', () => {
  it('lands on exec for the matrix the live projection emits', () => {
    // The regression (AAASM-5125): the page hard-coded `write`, which the
    // projection models on the Filesystem column alone — one populated column
    // beside a wall of n/a on the flagship governance page.
    const agents = [projectedAgent('a'), projectedAgent('b')]
    expect(defaultVerb(agents, RESOURCES)).toBe('exec')
    expect(defaultVerb(agents, RESOURCES)).not.toBe('write')
  })

  it('picks whichever verb the loaded grid actually populates, not a fixed one', () => {
    // A filesystem-only fleet has no exec cells at all; the default must follow
    // the data rather than assume today's winner is permanent.
    const agents = [agent('a', { filesystem: cell({ read: 'allow', write: 'deny' }) })]
    expect(defaultVerb(agents, [RESOURCES[0]])).toBe('read')
  })

  it.each<[Verb]>([['read'], ['write'], ['delete'], ['exec']])(
    'selects %s when it is the only verb carrying a decision',
    (verb) => {
      const agents = [agent('a', { filesystem: cell({ [verb]: 'allow' }) })]
      expect(defaultVerb(agents, RESOURCES)).toBe(verb)
    },
  )

  it('counts a missing cap cell as unpopulated, like an explicit na', () => {
    // A column outside an agent's scope is absent from `caps` entirely; it must
    // not be credited to any verb.
    const agents = [agent('a', { terminal: cell({ exec: 'allow' }) })]
    expect(defaultVerb(agents, RESOURCES)).toBe('exec')
  })

  it('is deterministic on a grid that gives no reason to prefer a verb', () => {
    // Never reached through the UI — the page renders EmptyState/LoadingState
    // instead — but the function must still be total.
    expect(defaultVerb([], RESOURCES)).toBe('read')
    expect(defaultVerb([agent('a', { filesystem: cell({}) })], RESOURCES)).toBe('read')
  })
})
