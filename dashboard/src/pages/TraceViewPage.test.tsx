import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { TraceViewPage } from './TraceViewPage'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/agents/:id/trace/:sessionId" element={<TraceViewPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('TraceViewPage', () => {
  it('renders the agent id and session id from URL params in the header', () => {
    renderAt('/agents/agent-001/trace/session-abc')

    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading).toHaveTextContent('agent-001')
    expect(heading).toHaveTextContent('session-abc')
  })

  it('exposes a back link to the agent detail page', () => {
    renderAt('/agents/agent-001/trace/session-abc')

    const link = screen.getByRole('link', { name: /Back to agent/i })
    expect(link).toHaveAttribute('href', '/agents/agent-001')
  })

  it('mounts the timeline placeholder slot', () => {
    renderAt('/agents/agent-001/trace/session-abc')
    expect(screen.getByTestId('trace-timeline-placeholder')).toBeInTheDocument()
  })
})
