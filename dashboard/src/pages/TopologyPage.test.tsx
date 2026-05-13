import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TopologyPage } from './TopologyPage'

describe('TopologyPage', () => {
  it('renders the Topology header with agent + team meta', () => {
    render(<TopologyPage />)
    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading).toHaveTextContent('Topology')
    expect(screen.getByTestId('topology-meta')).toHaveTextContent(/0 agents/)
    expect(screen.getByTestId('topology-meta')).toHaveTextContent(/0 teams/)
  })

  it('mounts the graph placeholder slot', () => {
    render(<TopologyPage />)
    const slot = screen.getByTestId('topology-graph-placeholder')
    expect(slot).toBeInTheDocument()
    expect(slot).toHaveAttribute('aria-label', 'Topology graph')
  })

  it('mounts the node-detail panel placeholder slot', () => {
    render(<TopologyPage />)
    const slot = screen.getByTestId('topology-panel-placeholder')
    expect(slot).toBeInTheDocument()
    expect(slot).toHaveAttribute('aria-label', 'Node detail panel')
  })
})
