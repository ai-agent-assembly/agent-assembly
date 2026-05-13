/**
 * REST helpers for the Live Ops row-action menu (AAASM-1334).
 *
 * The gateway does not yet expose per-op `pause` / `resume` / `terminate`
 * endpoints — they will be added under a separate sub-ticket of
 * AAASM-1282. Until then these helpers post against the conventional
 * paths and surface any 4xx/5xx so the LiveOpsPage rollback path can
 * fire on a real failure.
 *
 * The helpers use raw `fetch` instead of the openapi-fetch client
 * because the paths are not yet in the generated schema. Auth header
 * mirrors `api/client.ts` — pulls the JWT from `localStorage`.
 */

type OpAction = 'pause' | 'resume' | 'terminate'

function buildUrl(id: string, action: OpAction): string {
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ''
  return `${base}/api/v1/ops/${encodeURIComponent(id)}/${action}`
}

function authHeader(): Record<string, string> {
  if (typeof localStorage === 'undefined') return {}
  const token = localStorage.getItem('aa_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function postOpAction(id: string, action: OpAction): Promise<void> {
  const response = await fetch(buildUrl(id, action), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeader() },
  })
  if (!response.ok) {
    const body = await response.text().catch(() => '')
    throw new Error(
      `Failed to ${action} op ${id}: ${response.status}${body ? ` — ${body}` : ''}`,
    )
  }
}

export function pauseOp(id: string): Promise<void> {
  return postOpAction(id, 'pause')
}

export function resumeOp(id: string): Promise<void> {
  return postOpAction(id, 'resume')
}

export function terminateOp(id: string): Promise<void> {
  return postOpAction(id, 'terminate')
}
