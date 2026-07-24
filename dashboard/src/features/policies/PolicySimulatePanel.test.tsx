import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { PolicySimulatePanel } from './PolicySimulatePanel'
import type { SimulatePolicyResponse } from './api'

function renderPanel(onClose = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const utils = render(
    <QueryClientProvider client={client}>
      <PolicySimulatePanel open onClose={onClose} />
    </QueryClientProvider>,
  )
  return { ...utils, onClose }
}

let post: Mock

beforeEach(() => {
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('PolicySimulatePanel', () => {
  it('is not rendered when closed', () => {
    const client = new QueryClient()
    render(
      <QueryClientProvider client={client}>
        <PolicySimulatePanel open={false} onClose={vi.fn()} />
      </QueryClientProvider>,
    )
    expect(screen.queryByTestId('policy-simulate')).not.toBeInTheDocument()
  })

  it('disables Run until a tool is entered, then posts the request body', async () => {
    const user = userEvent.setup()
    post.mockResolvedValue({
      data: {
        verdict: 'allow',
        matched_rule: null,
        reason: 'allowed by policy',
        redacted: false,
      } satisfies SimulatePolicyResponse,
    })
    renderPanel()

    // agent defaults to research-bot-04; tool is empty → Run disabled.
    expect(screen.getByTestId('simulate-run-btn')).toBeDisabled()

    await user.type(screen.getByTestId('simulate-tool-input'), 'gmail_send')
    await user.type(screen.getByTestId('simulate-target-input'), 'a@acme.com')
    expect(screen.getByTestId('simulate-run-btn')).toBeEnabled()

    await user.click(screen.getByTestId('simulate-run-btn'))

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/v1/policies/simulate', {
        body: { agent_id: 'research-bot-04', tool: 'gmail_send', target: 'a@acme.com' },
      }),
    )
    expect(await screen.findByTestId('simulate-verdict')).toHaveAttribute('data-verdict', 'allow')
  })

  it('omits an empty target from the request body', async () => {
    const user = userEvent.setup()
    post.mockResolvedValue({
      data: { verdict: 'allow', matched_rule: null, reason: 'ok', redacted: false },
    })
    renderPanel()
    await user.type(screen.getByTestId('simulate-tool-input'), 'web_search')
    await user.click(screen.getByTestId('simulate-run-btn'))
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/v1/policies/simulate', {
        body: { agent_id: 'research-bot-04', tool: 'web_search', target: undefined },
      }),
    )
  })

  it('renders a deny verdict with the matched rule and reason', async () => {
    const user = userEvent.setup()
    post.mockResolvedValue({
      data: {
        verdict: 'deny',
        matched_rule: 'tool denied by policy',
        reason: 'tool denied by policy',
        redacted: false,
      } satisfies SimulatePolicyResponse,
    })
    renderPanel()
    await user.type(screen.getByTestId('simulate-tool-input'), 'shell')
    await user.click(screen.getByTestId('simulate-run-btn'))

    expect(await screen.findByTestId('simulate-verdict')).toHaveAttribute('data-verdict', 'deny')
    expect(screen.getByTestId('simulate-matched-rule')).toHaveTextContent('tool denied by policy')
    expect(screen.getByTestId('simulate-reason')).toHaveTextContent('tool denied by policy')
  })

  it('renders an approval verdict with its matched rule and reason', async () => {
    const user = userEvent.setup()
    post.mockResolvedValue({
      data: {
        verdict: 'approval',
        matched_rule: 'requires human approval',
        reason: 'tool requires approval before execution',
        redacted: false,
      } satisfies SimulatePolicyResponse,
    })
    renderPanel()
    await user.clear(screen.getByTestId('simulate-agent-input'))
    await user.type(screen.getByTestId('simulate-agent-input'), 'finance-bot-01')
    await user.type(screen.getByTestId('simulate-tool-input'), 'wire_transfer')
    await user.click(screen.getByTestId('simulate-run-btn'))

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/v1/policies/simulate', {
        body: { agent_id: 'finance-bot-01', tool: 'wire_transfer', target: undefined },
      }),
    )
    const verdict = await screen.findByTestId('simulate-verdict')
    expect(verdict).toHaveAttribute('data-verdict', 'approval')
    expect(verdict).toHaveClass('policy-simulate__verdict--approval')
    expect(screen.getByTestId('simulate-matched-rule')).toHaveTextContent('requires human approval')
    expect(screen.getByTestId('simulate-reason')).toHaveTextContent(
      'tool requires approval before execution',
    )
  })

  it('renders a narrow verdict and the scrubbed indicator when redacted', async () => {
    const user = userEvent.setup()
    post.mockResolvedValue({
      data: {
        verdict: 'narrow',
        matched_rule: 'sensitive content scrubbed',
        reason: 'allowed after redacting sensitive content',
        redacted: true,
      } satisfies SimulatePolicyResponse,
    })
    renderPanel()
    await user.type(screen.getByTestId('simulate-tool-input'), 'gmail_send')
    await user.click(screen.getByTestId('simulate-run-btn'))

    expect(await screen.findByTestId('simulate-verdict')).toHaveAttribute('data-verdict', 'narrow')
    expect(screen.getByTestId('simulate-redacted')).toBeInTheDocument()
  })

  it('surfaces an error banner when the request fails', async () => {
    const user = userEvent.setup()
    post.mockResolvedValue({ error: { detail: 'boom' } })
    renderPanel()
    await user.type(screen.getByTestId('simulate-tool-input'), 'shell')
    await user.click(screen.getByTestId('simulate-run-btn'))
    expect(await screen.findByTestId('simulate-error')).toBeInTheDocument()
  })

  it('closes via the close button', async () => {
    const user = userEvent.setup()
    const { onClose } = renderPanel()
    await user.click(screen.getByTestId('policy-simulate-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
