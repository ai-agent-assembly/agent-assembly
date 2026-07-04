/**
 * Base-URL + bearer-auth fetch helper for the analytics data path.
 *
 * The `/api/v1/analytics/*` endpoints are not yet in `openapi/v1.yaml`, so the
 * typed `openapi-fetch` client in `api/client.ts` cannot reach them. This thin
 * wrapper mirrors that client's convention — prepend `VITE_API_BASE_URL` and
 * attach the stored `aa_token` as a `Authorization: Bearer` header — so every
 * analytics hook authenticates and targets the API origin the same way the rest
 * of the app does (see also `features/trace/api.ts`, `features/alerts/api.ts`).
 * Swap these hooks to the typed `api.GET` client once the schema covers them
 * (backend work tracked under AAASM-4138).
 */
export async function analyticsFetch<T>(path: string): Promise<T> {
  const base = import.meta.env.VITE_API_BASE_URL ?? ''
  const token = localStorage.getItem('aa_token')
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(`${base}${path}`, { headers })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<T>
}
