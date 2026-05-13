import { createContext } from 'react'

/**
 * State + actions exposed by `useTraceDrawer()`. The provider owns the
 * `open(agentId, sessionId)` and `close()` actions; consumers (topology
 * node panel, audit log link, etc.) call `open()` to surface the trace
 * drawer at the shell level.
 *
 * Lives in its own module so `TraceDrawerProvider.tsx` only exports a
 * component (satisfies `react-refresh/only-export-components`).
 */
export interface TraceDrawerState {
  readonly agentId: string | null
  readonly sessionId: string | null
}

export interface TraceDrawerContextValue {
  readonly state: TraceDrawerState
  open(agentId: string, sessionId: string): void
  close(): void
}

export const TraceDrawerContext = createContext<TraceDrawerContextValue | null>(null)
