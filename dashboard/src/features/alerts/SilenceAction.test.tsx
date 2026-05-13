import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SilenceAction } from './SilenceAction'
import { ToastProvider } from '../../components/ToastProvider'

interface Call {
  url: string
  init: RequestInit
}
let calls: Call[]

beforeEach(() => {
  calls = []
  localStorage.setItem('aa_token', 'test-token')
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init })
      return {
        ok: true,
        status: 201,
        json: async () => ({
          silenceId: 'sil-1',
          alertId: 'a-1',
          startsAt: '2026-05-14T09:00:00Z',
          expiresAt: '2026-05-14T10:00:00Z',
          reason: null,
          createdBy: 'user-1',
        }),
      } as Response
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
})

function Wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}

describe('SilenceAction', () => {
  it('dispatches useSilenceAlertMutation with the chosen preset', async () => {
    const user = userEvent.setup()
    render(<SilenceAction alertId="a-1" />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('silence-action-duration-4h'))
    await user.click(screen.getByTestId('silence-action-submit'))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0].url).toBe('/api/v1/alerts/silence')
    expect(JSON.parse(calls[0].init.body as string)).toEqual({
      alert_id: 'a-1',
      duration_seconds: 4 * 60 * 60,
      reason: undefined,
    })
  })

  it('respects custom minutes input', async () => {
    const user = userEvent.setup()
    render(<SilenceAction alertId="a-1" />, { wrapper: Wrapper })
    await user.click(screen.getByTestId('silence-action-duration-custom'))
    const customInput = screen.getByTestId('silence-action-custom-minutes') as HTMLInputElement
    await user.clear(customInput)
    await user.type(customInput, '15')
    await user.click(screen.getByTestId('silence-action-submit'))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(JSON.parse(calls[0].init.body as string).duration_seconds).toBe(15 * 60)
  })

  it('renders a read-only line when the alert is already silenced', () => {
    render(<SilenceAction alertId="a-1" silenced />, { wrapper: Wrapper })
    expect(screen.getByTestId('silence-action-already')).toBeInTheDocument()
    expect(screen.queryByTestId('silence-action-submit')).not.toBeInTheDocument()
  })
})
