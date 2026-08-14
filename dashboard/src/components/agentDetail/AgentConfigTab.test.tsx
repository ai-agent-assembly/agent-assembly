import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { AgentConfigTab } from './AgentConfigTab'
import * as agentPoliciesApi from '../../features/capability/useAgentPolicies'
import type { Agent } from '../../features/agents/api'
import type { Policy } from '../../features/capability/types'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const AGENT = {
  id: 'abc123',
  name: 'alpha-agent',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  session_count: 10,
  policy_violations_count: 4,
  is_flagged: true,
  tool_names: [],
  metadata: { owner: 'alice', mode: 'shadow' },
  pid: null,
} as unknown as Agent

function mockPolicies(data: Policy[]) {
  vi.spyOn(agentPoliciesApi, 'useAgentPoliciesQuery').mockReturnValue(
    mockQuery<Policy[]>({ data, isLoading: false, isError: false }),
  )
}

afterEach(() => vi.restoreAllMocks())

describe('AgentConfigTab', () => {
  it('renders YAML derived from the fields the dashboard already has', () => {
    mockPolicies([])
    render(<AgentConfigTab agent={AGENT} />)
    const yaml = screen.getByTestId('agent-config-yaml')
    expect(yaml).toHaveTextContent('id: "abc123"')
    expect(yaml).toHaveTextContent('framework: langgraph')
    expect(yaml).toHaveTextContent('owner: "@alice"')
    expect(yaml).toHaveTextContent('status: active')
    expect(yaml).toHaveTextContent('did: did:agent:alice:abc123')
    expect(yaml).toHaveTextContent('mode: shadow')
  })

  it('marks every backend-only key as pending without fabricating a value', () => {
    mockPolicies([])
    render(<AgentConfigTab agent={AGENT} />)
    const pending = screen.getAllByTestId('agent-config-pending-line')
    // issuer, expiry, fail_open, rate_limit, observability
    expect(pending).toHaveLength(5)
    for (const line of pending) expect(line).toHaveTextContent('pending backend')
  })

  it('lists the agent-scoped policies when present', () => {
    mockPolicies([
      { id: 'P-066', name: 'narrow research-bot writes', version: '3', scope: 'tag:research', status: 'proposed', hits24h: 0, affects: ['abc123'], rules: [] },
    ])
    render(<AgentConfigTab agent={AGENT} />)
    expect(screen.getByTestId('agent-config-yaml')).toHaveTextContent('- P-066 # narrow research-bot writes')
  })

  it('renders an empty policy list when the agent has none', () => {
    mockPolicies([])
    render(<AgentConfigTab agent={AGENT} />)
    expect(screen.getByTestId('agent-config-yaml')).toHaveTextContent('policies: []')
  })

  it('falls back to the agent-assembly owner slug when owner metadata is missing', () => {
    mockPolicies([])
    render(<AgentConfigTab agent={{ ...AGENT, metadata: {} } as Agent} />)
    expect(screen.getByTestId('agent-config-yaml')).toHaveTextContent('did:agent:agent-assembly:abc123')
  })
})
