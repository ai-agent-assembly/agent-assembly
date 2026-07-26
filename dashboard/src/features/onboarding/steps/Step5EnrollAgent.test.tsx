import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Step5EnrollAgent } from './Step5EnrollAgent'
import { api } from '../../../api/client'
import { EMPTY_STATE, type WizardState } from '../types'

// See the header of `features/onboarding/api.test.tsx` for why the client, not
// `globalThis.fetch`, is the mock boundary.
vi.mock('../../../api/client', () => ({ api: { GET: vi.fn() } }))

const apiGet = api.GET as unknown as ReturnType<typeof vi.fn>

const ENROLLED_STATE: WizardState = { ...EMPTY_STATE, enrolled: true }

const AGENT = {
  id: 'agent-1',
  name: 'research-bot',
  framework: 'langgraph',
  version: '0.0.1',
  status: 'active',
  tool_names: [],
  metadata: {},
  session_count: 0,
  policy_violations_count: 0,
  active_sessions: [],
  recent_events: [],
  recent_traces: [],
  last_event: '2026-07-26T09:00:00Z',
  layer: null,
  pid: null,
}

function page(items: unknown[], total = items.length) {
  return {
    data: { items, page: 1, per_page: 100, total },
    error: undefined,
    response: { ok: true, status: 200 } as Response,
  }
}

function failure() {
  return {
    data: undefined,
    error: { detail: 'boom' },
    response: { ok: false, status: 503 } as Response,
  }
}

function renderStep(state: WizardState, onEnrolled = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return {
    onEnrolled,
    ...render(<Step5EnrollAgent state={state} onEnrolled={onEnrolled} />, { wrapper }),
  }
}

beforeEach(() => {
  apiGet.mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Step5EnrollAgent — AAASM-5133 real enrollment', () => {
  it('claims no count before the registry has been asked', () => {
    const { onEnrolled } = renderStep(EMPTY_STATE)

    expect(screen.getByTestId('onboarding-enroll-count-value')).toHaveAttribute(
      'data-truth-state',
      'not-evaluated',
    )
    expect(screen.getByTestId('onboarding-enroll-count')).not.toHaveTextContent('0')
    expect(apiGet).not.toHaveBeenCalled()
    expect(onEnrolled).not.toHaveBeenCalled()
  })

  it('reports the registry’s own total once the listener starts', async () => {
    apiGet.mockResolvedValue(page([AGENT], 1))
    const { onEnrolled } = renderStep(EMPTY_STATE)

    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    await waitFor(() =>
      expect(screen.getByTestId('onboarding-enroll-count-value')).toHaveTextContent('1'),
    )
    expect(screen.getByTestId('onboarding-enroll-connected')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-enroll-agent-agent-1')).toHaveTextContent('research-bot')
    expect(onEnrolled).toHaveBeenCalledTimes(1)
  })

  it('reports an answered but empty registry as a measured zero, not as an enrollment', async () => {
    apiGet.mockResolvedValue(page([], 0))
    const { onEnrolled } = renderStep(EMPTY_STATE)

    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    await waitFor(() =>
      expect(screen.getByTestId('onboarding-enroll-count-value')).toHaveTextContent('0'),
    )
    expect(screen.getByTestId('onboarding-enroll-count-value')).toHaveAttribute(
      'data-truth-state',
      'known',
    )
    expect(screen.getByTestId('onboarding-enroll-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('onboarding-enroll-connected')).toBeNull()
    expect(onEnrolled).not.toHaveBeenCalled()
  })

  it('renders a failed poll as unavailable — never as zero agents', async () => {
    apiGet.mockResolvedValue(failure())
    const { onEnrolled } = renderStep(EMPTY_STATE)

    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    await waitFor(() =>
      expect(screen.getByTestId('onboarding-enroll-count-value')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      ),
    )
    expect(screen.getByTestId('onboarding-enroll-count')).not.toHaveTextContent('0')
    const absence = screen.getByTestId('onboarding-enroll-absent')
    expect(absence).toHaveAttribute('data-truth-state', 'unavailable')
    // A failed request is the one absence announced assertively.
    expect(absence).toHaveAttribute('role', 'alert')
    expect(screen.queryByTestId('onboarding-enroll-connected')).toBeNull()
    expect(onEnrolled).not.toHaveBeenCalled()
  })

  it('re-asks the registry on resume instead of trusting the persisted enrolled flag', async () => {
    apiGet.mockResolvedValue(page([], 0))
    const { onEnrolled } = renderStep(ENROLLED_STATE)

    // No "start listener" button: a resumed session goes straight to polling.
    expect(screen.queryByTestId('onboarding-enroll-start')).toBeNull()
    await waitFor(() =>
      expect(screen.getByTestId('onboarding-enroll-count-value')).toHaveTextContent('0'),
    )
    // The gateway says there is no agent, so the step does not show the badge
    // the persisted flag would have implied.
    expect(screen.queryByTestId('onboarding-enroll-connected')).toBeNull()
    expect(onEnrolled).not.toHaveBeenCalled()
  })

  it('shows what the registry reports about each agent, with no invented traffic', async () => {
    apiGet.mockResolvedValue(page([AGENT, { ...AGENT, id: 'agent-2', name: 'etl', last_event: null }], 2))
    renderStep(EMPTY_STATE)

    fireEvent.click(screen.getByTestId('onboarding-enroll-start'))

    await waitFor(() =>
      expect(screen.getByTestId('onboarding-enroll-agent-agent-2')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('onboarding-enroll-agent-last-event-agent-1')).toHaveTextContent(
      '2026-07-26T09:00:00Z',
    )
    // A missing last_event folds to the shared marker rather than to a
    // plausible-looking timestamp.
    expect(screen.getByTestId('onboarding-enroll-agent-last-event-agent-2')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )

    const pings = screen.getByTestId('onboarding-enroll-pings')
    for (const fabrication of [
      '14:02:11',
      'phone-home',
      'capability.list',
      'gmail.read',
      'allowed-by-baseline',
      'identity-verified',
    ]) {
      expect(pings).not.toHaveTextContent(fabrication)
    }
  })

  it('does not poll while idle', () => {
    apiGet.mockResolvedValue(page([AGENT], 1))
    renderStep(EMPTY_STATE)

    expect(screen.getByTestId('onboarding-enroll-start')).toBeInTheDocument()
    expect(apiGet).not.toHaveBeenCalled()
  })
})
