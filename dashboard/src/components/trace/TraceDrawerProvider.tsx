import { useCallback, useMemo, useState, type ReactNode } from 'react'
import {
  TraceDrawerContext,
  type TraceDrawerContextValue,
  type TraceDrawerState,
} from './TraceDrawerContext'

/**
 * Mounts the trace-drawer state at the shell level so any routed page
 * can call `useTraceDrawer().open(agentId, sessionId)` to surface the
 * trace overlay without leaving its own page.
 *
 * AAASM-1340 — paired with `<TraceDrawer />` which subscribes to the
 * same context and renders the drawer body.
 */
export function TraceDrawerProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<TraceDrawerState>({ agentId: null, sessionId: null })

  const open = useCallback((agentId: string, sessionId: string) => {
    setState({ agentId, sessionId })
  }, [])

  const close = useCallback(() => {
    setState({ agentId: null, sessionId: null })
  }, [])

  const value = useMemo<TraceDrawerContextValue>(
    () => ({ state, open, close }),
    [state, open, close],
  )

  return <TraceDrawerContext.Provider value={value}>{children}</TraceDrawerContext.Provider>
}
