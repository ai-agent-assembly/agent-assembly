import { useContext } from 'react'
import { TraceDrawerContext, type TraceDrawerContextValue } from './TraceDrawerContext'

/**
 * Access the trace drawer state + actions from any routed page wrapped
 * by `<TraceDrawerProvider>` at the shell level (AAASM-1340).
 *
 * Throws if used outside the provider — surfaces wiring bugs early.
 */
export function useTraceDrawer(): TraceDrawerContextValue {
  const ctx = useContext(TraceDrawerContext)
  if (!ctx) {
    throw new Error('useTraceDrawer must be used inside <TraceDrawerProvider>')
  }
  return ctx
}
