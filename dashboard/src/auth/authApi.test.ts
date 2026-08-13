import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import {
  AuthApiError,
  authMethods,
  confirmPasswordReset,
  login,
  register,
  requestPasswordReset,
} from './authApi'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('authApi.login', () => {
  it('returns the access token on success', async () => {
    vi.spyOn(api, 'POST').mockResolvedValue({
      data: { access_token: 'jwt', expires_in: 900 },
      response: new Response(null, { status: 200 }),
    } as never)

    await expect(login('user@example.com', 'hunter2!', true)).resolves.toEqual({
      accessToken: 'jwt',
      expiresIn: 900,
    })
  })

  it('maps 401 to an invalid-credentials AuthApiError', async () => {
    vi.spyOn(api, 'POST').mockResolvedValue({
      error: {},
      response: new Response(null, { status: 401 }),
    } as never)

    await expect(login('user@example.com', 'bad')).rejects.toMatchObject({
      status: 401,
      message: 'Invalid email or password.',
    })
  })

  it('maps 423 to a locked error carrying retry-after seconds', async () => {
    vi.spyOn(api, 'POST').mockResolvedValue({
      error: {},
      response: new Response(null, { status: 423, headers: { 'retry-after': '120' } }),
    } as never)

    await expect(login('user@example.com', 'hunter2!')).rejects.toMatchObject({
      status: 423,
      retryAfterSeconds: 120,
    })
  })
})

describe('authApi.register', () => {
  it('returns the access token on success (no tenant name sent)', async () => {
    const post = vi.spyOn(api, 'POST').mockResolvedValue({
      data: { access_token: 'jwt', expires_in: 900, user_id: 'u1' },
      response: new Response(null, { status: 201 }),
    } as never)

    await expect(register('new@example.com', 'hunter2!')).resolves.toEqual({
      accessToken: 'jwt',
      expiresIn: 900,
    })
    expect(post).toHaveBeenCalledWith('/api/v1/auth/register', {
      body: { email: 'new@example.com', password: 'hunter2!' },
    })
  })

  it('maps 409 to an email-exists AuthApiError', async () => {
    vi.spyOn(api, 'POST').mockResolvedValue({
      error: {},
      response: new Response(null, { status: 409 }),
    } as never)

    await expect(register('taken@example.com', 'hunter2!')).rejects.toMatchObject({ status: 409 })
  })
})

describe('authApi.authMethods', () => {
  it('narrows the wire methods to the known set', async () => {
    vi.spyOn(api, 'GET').mockResolvedValue({
      data: { methods: ['api_key', 'password', 'sorcery'] },
      response: new Response(null, { status: 200 }),
    } as never)

    await expect(authMethods()).resolves.toEqual(['api_key', 'password'])
  })
})

describe('authApi password reset (enumeration-safe)', () => {
  it('requestPasswordReset posts the email and resolves regardless of status', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 202 }))

    await expect(requestPasswordReset('user@example.com')).resolves.toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/password/reset'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('requestPasswordReset never rejects even on a server error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 500 }))
    await expect(requestPasswordReset('user@example.com')).resolves.toBeUndefined()
  })

  it('confirmPasswordReset resolves on success', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
    await expect(confirmPasswordReset('tok', 'newpass12')).resolves.toBeUndefined()
  })

  it('confirmPasswordReset maps 422 to an expired-token error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 422 }))
    await expect(confirmPasswordReset('tok', 'newpass12')).rejects.toBeInstanceOf(AuthApiError)
    await expect(confirmPasswordReset('tok', 'newpass12')).rejects.toMatchObject({ status: 422 })
  })
})
