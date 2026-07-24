import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { AgentTrafficTab } from './AgentTrafficTab'
import * as trafficApi from '../../features/analytics/useAgentTrafficQuery'
import type { AgentTraffic } from '../../features/analytics/useAgentTrafficQuery'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

afterEach(() => vi.restoreAllMocks())

describe('AgentTrafficTab', () => {
  it('shows the loading state while the traffic query is in flight', () => {
    vi.spyOn(trafficApi, 'useAgentTrafficQuery').mockReturnValue(
      mockQuery<AgentTraffic>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    render(<AgentTrafficTab agentId="a1" />)
    expect(screen.getByTestId('agent-traffic-loading')).toBeInTheDocument()
  })

  it('shows an error state and retries on demand', () => {
    const refetch = vi.fn()
    vi.spyOn(trafficApi, 'useAgentTrafficQuery').mockReturnValue(
      mockQuery<AgentTraffic>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    render(<AgentTrafficTab agentId="a1" />)
    expect(screen.getByTestId('agent-traffic-error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('renders the empty tool state while still showing the action total', () => {
    vi.spyOn(trafficApi, 'useAgentTrafficQuery').mockReturnValue(
      mockQuery<AgentTraffic>({
        data: { tools: [], totalActions: 0 },
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentTrafficTab agentId="a1" />)
    expect(screen.getByTestId('agent-traffic-tab')).toBeInTheDocument()
    expect(screen.getByTestId('agent-traffic-total')).toHaveTextContent('0')
    expect(screen.getByTestId('agent-traffic-empty')).toBeInTheDocument()
  })

  it('renders per-tool bars sorted by calls with the action total', () => {
    vi.spyOn(trafficApi, 'useAgentTrafficQuery').mockReturnValue(
      mockQuery<AgentTraffic>({
        data: {
          totalActions: 1421,
          tools: [
            { name: 'gmail.send', calls: 200, errorRate: 0.02 },
            { name: 'pg.users', calls: 1284, errorRate: 0 },
          ],
        },
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentTrafficTab agentId="a1" />)
    expect(screen.getByTestId('agent-traffic-total')).toHaveTextContent('1,421')
    expect(screen.getByTestId('traffic-tool-pg.users')).toHaveTextContent('1,284')
    expect(screen.getByTestId('traffic-tool-gmail.send')).toHaveTextContent('2.0%')
    // Most-called tool renders first.
    const rows = screen.getByTestId('agent-traffic-tools').querySelectorAll('[data-testid^="traffic-tool-"]')
    expect(rows[0]).toHaveAttribute('data-testid', 'traffic-tool-pg.users')
  })
})
