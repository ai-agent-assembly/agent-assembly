import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { Approval } from './api'
import type { components } from '../../api/generated/schema'

type GovernanceEvent = components['schemas']['GovernanceEvent']
type ApprovalPayload = components['schemas']['ApprovalPayload']

const MAX_BACKOFF_MS = 8000

function buildWsUrl(): string {
  const base = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ''
  const wsBase = base
    ? base.replace(/^https/, 'wss').replace(/^http/, 'ws')
    : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
  const token = localStorage.getItem('aa_token')
  const query = ['types=approval', token ? `token=${encodeURIComponent(token)}` : '']
    .filter(Boolean)
    .join('&')
  return `${wsBase}/api/v1/ws/events?${query}`
}

export function useApprovalsStream(): { connected: boolean } {
  const queryClient = useQueryClient()
  const [connected, setConnected] = useState(false)
  const backoffRef = useRef(250)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const deadRef = useRef(false)

  useEffect(() => {
    deadRef.current = false

    function connect() {
      if (deadRef.current) return
      const ws = new WebSocket(buildWsUrl())
      wsRef.current = ws

      ws.onopen = () => {
        if (deadRef.current) { ws.close(); return }
        setConnected(true)
        backoffRef.current = 250
      }

      ws.onmessage = (evt) => {
        try {
          const event = JSON.parse(evt.data as string) as GovernanceEvent
          if (event.event_type !== 'approval') return
          const payload = event.payload as ApprovalPayload
          const incoming: Approval = {
            id: payload.request_id,
            agent_id: event.agent_id,
            action: payload.action,
            reason: payload.condition_triggered,
            status: 'pending',
            created_at: event.timestamp,
            // WS `expires_at` is unix seconds; the REST shape uses RFC 3339,
            // so convert to ISO 8601 for consistency with the cached list view.
            expires_at: new Date(payload.expires_at * 1000).toISOString(),
            routing_status: null,
            team_id: null,
          }
          queryClient.setQueryData<Approval[]>(['approvals'], (prev) => {
            if (!prev) return [incoming]
            if (prev.some((a) => a.id === incoming.id)) return prev
            return [incoming, ...prev]
          })
        } catch {
          // Ignore malformed frames
        }
      }

      ws.onclose = () => {
        setConnected(false)
        if (deadRef.current) return
        const delay = backoffRef.current
        backoffRef.current = Math.min(delay * 2, MAX_BACKOFF_MS)
        timerRef.current = setTimeout(connect, delay)
      }

      ws.onerror = () => { ws.close() }
    }

    connect()

    return () => {
      deadRef.current = true
      if (timerRef.current) clearTimeout(timerRef.current)
      wsRef.current?.close()
    }
  }, [queryClient])

  return { connected }
}
