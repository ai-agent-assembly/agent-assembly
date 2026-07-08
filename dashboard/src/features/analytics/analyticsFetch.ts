import { getToken } from '../../auth/tokenStorage'

/**
 * Base-URL + bearer-auth fetch helper for the analytics data path.
 *
 * The `/api/v1/analytics/*` endpoints are now defined in `openapi/v1.yaml`, but
 * the analytics hooks still call this thin wrapper rather than the typed
 * `openapi-fetch` client in `api/client.ts`. It mirrors that client's
 * convention — prepend `VITE_API_BASE_URL` and attach the stored `aa_token` as
 * an `Authorization: Bearer` header — so every analytics hook authenticates and
 * targets the API origin the same way the rest of the app does (see also
 * `features/trace/api.ts`, `features/alerts/api.ts`). These hooks can be
 * migrated to the typed `api.GET` client now that the schema covers them.
 */
export async function analyticsFetch<T>(path: string): Promise<T> {
  const base = import.meta.env.VITE_API_BASE_URL ?? ''
  const token = getToken()
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(`${base}${path}`, { headers })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<T>
}
