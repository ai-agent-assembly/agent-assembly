/**
 * REST helpers for the Live Ops op-control affordances (AAASM-1334 /
 * AAASM-5074).
 *
 * The gateway now exposes the per-op and fleet-wide control endpoints these
 * helpers post against:
 *   - `POST /api/v1/ops/{id}/pause|resume|terminate` — per-op lifecycle
 *   - `POST /api/v1/ops/{id}/halt-agent` — halt the agent owning this op
 *   - `POST /api/v1/ops/global/halt` — fleet-wide kill switch
 * Any 4xx/5xx is surfaced so the LiveOpsPage rollback path fires on a real
 * failure.
 *
 * The helpers use raw `fetch` instead of the openapi-fetch client because the
 * op-control paths are not yet in the generated schema. Auth header mirrors
 * `api/client.ts` — pulls the JWT from the shared `tokenStorage` helper
 * (sessionStorage-backed since AAASM-4322).
 */

import { getToken } from '../../auth/tokenStorage'

type OpAction = 'pause' | 'resume' | 'terminate' | 'halt-agent'

function apiBase(): string {
  return (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ''
}

function buildUrl(id: string, action: OpAction): string {
  return `${apiBase()}/api/v1/ops/${encodeURIComponent(id)}/${action}`
}

function authHeader(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function post(url: string, failLabel: string): Promise<void> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeader() },
  })
  if (!response.ok) {
    const body = await response.text().catch(() => '')
    const detail = body ? ` — ${body}` : ''
    throw new Error(`${failLabel}: ${response.status}${detail}`)
  }
}

function postOpAction(id: string, action: OpAction): Promise<void> {
  return post(buildUrl(id, action), `Failed to ${action} op ${id}`)
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

/** Halt the agent owning `id` — stops every in-flight op for that agent. */
export function haltAgent(id: string): Promise<void> {
  return postOpAction(id, 'halt-agent')
}

/** Fleet-wide kill switch — halts all agents' operations at once. */
export function haltGlobal(): Promise<void> {
  return post(`${apiBase()}/api/v1/ops/global/halt`, 'Failed to halt all ops')
}
