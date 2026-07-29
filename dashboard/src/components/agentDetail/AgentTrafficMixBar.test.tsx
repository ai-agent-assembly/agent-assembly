import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { AgentTrafficMixBar } from './AgentTrafficMixBar'
import * as decisionMixApi from '../../features/analytics/useAgentDecisionMixQuery'
import type { AgentDecisionMix } from '../../features/analytics/useAgentDecisionMixQuery'

function mockQuery(partial: Partial<UseQueryResult<AgentDecisionMix | null, Error>>) {
  return partial as unknown as UseQueryResult<AgentDecisionMix | null, Error>
}

function mockMix(partial: Partial<UseQueryResult<AgentDecisionMix | null, Error>>) {
  vi.spyOn(decisionMixApi, 'useAgentDecisionMixQuery').mockReturnValue(mockQuery(partial))
}

const AGENT = 'abc123'

function row(overrides: Partial<AgentDecisionMix>): AgentDecisionMix {
  return {
    agent_id: AGENT,
    allow: 0,
    narrow: 0,
    scrub: 0,
    pending: 0,
    deny: 0,
    ...overrides,
  } as AgentDecisionMix
}

afterEach(() => vi.restoreAllMocks())

describe('AgentTrafficMixBar', () => {
  it('shows a loading placeholder while the query is pending', () => {
    mockMix({ data: undefined, isLoading: true, isError: false })
    render(<AgentTrafficMixBar agentId={AGENT} />)
    expect(screen.getByTestId('agent-detail-traffic-mix-loading')).toBeInTheDocument()
  })

  it('shows an honest empty state when the agent has no row (null)', () => {
    mockMix({ data: null, isLoading: false, isError: false })
    render(<AgentTrafficMixBar agentId={AGENT} />)
    expect(screen.getByTestId('agent-detail-traffic-mix-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('agent-detail-traffic-mix-allow')).not.toBeInTheDocument()
  })

  it('shows the empty state on a fetch error rather than a fabricated bar', () => {
    mockMix({ data: undefined, isLoading: false, isError: true })
    render(<AgentTrafficMixBar agentId={AGENT} />)
    expect(screen.getByTestId('agent-detail-traffic-mix-empty')).toBeInTheDocument()
  })

  it('shows the empty state when every bucket is zero (zero total)', () => {
    mockMix({ data: row({}), isLoading: false, isError: false })
    render(<AgentTrafficMixBar agentId={AGENT} />)
    expect(screen.getByTestId('agent-detail-traffic-mix-empty')).toBeInTheDocument()
  })

  it('renders a segment per non-zero decision and omits zero-count lanes', () => {
    // narrow is always 0 (no audit source) — its lane must not render.
    mockMix({ data: row({ allow: 80, scrub: 15, deny: 5 }), isLoading: false, isError: false })
    render(<AgentTrafficMixBar agentId={AGENT} />)

    expect(screen.getByTestId('agent-detail-traffic-mix-allow')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-traffic-mix-scrub')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-traffic-mix-deny')).toBeInTheDocument()
    // Zero-count lanes (narrow, pending) render no segment.
    expect(screen.queryByTestId('agent-detail-traffic-mix-narrow')).not.toBeInTheDocument()
    expect(screen.queryByTestId('agent-detail-traffic-mix-pending')).not.toBeInTheDocument()
  })

  it('labels a wide segment with its name and count but a narrow one with the count only', () => {
    // allow = 96% (≥8% → labelled), deny = 4% (<8% → count only).
    mockMix({ data: row({ allow: 96, deny: 4 }), isLoading: false, isError: false })
    render(<AgentTrafficMixBar agentId={AGENT} />)
    expect(screen.getByTestId('agent-detail-traffic-mix-allow')).toHaveTextContent('allow 96')
    expect(screen.getByTestId('agent-detail-traffic-mix-deny')).toHaveTextContent('4')
    expect(screen.getByTestId('agent-detail-traffic-mix-deny')).not.toHaveTextContent('deny 4')
  })
})
