import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ResolveAction } from './ResolveAction'
import { ToastProvider } from '../../components/ToastProvider'
import { AuthContext, type AuthContextValue, type Scope } from '../../auth/AuthContext'

interface Call {
  url: string
  init: RequestInit
}
let calls: Call[]

beforeEach(() => {
  calls = []
  sessionStorage.setItem('aa_token', 'test-token')
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init })
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 'a-1', status: 'RESOLVED' }),
      } as Response
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  sessionStorage.clear()
})

function renderAction(scopes: Scope[] = ['write']) {
  const auth: AuthContextValue = {
    token: 'tok',
    scopes,
    login: async () => {},
    loginWithCredentials: async () => {},
    signup: async () => {},
    logout: () => {},
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <ToastProvider>
          <ResolveAction alertId="a-1" />
        </ToastProvider>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

describe('ResolveAction', () => {
  it('posts to the shipped resolve endpoint', async () => {
    const user = userEvent.setup()
    renderAction()
    await user.click(screen.getByTestId('resolve-action-submit'))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0].url).toBe('/api/v1/alerts/a-1/resolve')
    expect(calls[0].init.method).toBe('POST')
  })

  it('sends the typed reason', async () => {
    const user = userEvent.setup()
    renderAction()
    await user.type(screen.getByTestId('resolve-action-reason'), 'rolled back')
    await user.click(screen.getByTestId('resolve-action-submit'))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ reason: 'rolled back' })
  })

  it('is disabled for a read-only caller and issues no request', async () => {
    const user = userEvent.setup()
    renderAction(['read'])
    const submit = screen.getByTestId('resolve-action-submit')
    expect(submit).toBeDisabled()
    await user.click(submit)
    expect(calls).toHaveLength(0)
  })

  it('surfaces a failed resolve rather than reporting success', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) }) as Response),
    )
    renderAction()
    await user.click(screen.getByTestId('resolve-action-submit'))
    // The toast carries the failure; the button never claims the alert resolved.
    expect(await screen.findByText(/failed: 503/)).toBeInTheDocument()
  })

  it('is enabled for an admin caller', () => {
    renderAction(['admin'])
    expect(screen.getByTestId('resolve-action-submit')).toBeEnabled()
  })
})
