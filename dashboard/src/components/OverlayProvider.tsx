import { useCallback, useState, type ReactNode } from 'react'
import { OverlayContext, OVERLAY_NAMES, type OverlayName, type OverlayState } from './OverlayContext'

const INITIAL_STATES: Record<OverlayName, OverlayState> = Object.fromEntries(
  OVERLAY_NAMES.map((n) => [n, { open: false, props: {} }]),
) as Record<OverlayName, OverlayState>

export function OverlayProvider({ children }: { children: ReactNode }) {
  const [states, setStates] = useState<Record<OverlayName, OverlayState>>(INITIAL_STATES)

  const openOverlay = useCallback(
    (name: OverlayName, props: Record<string, unknown> = {}) => {
      setStates((prev) => ({ ...prev, [name]: { open: true, props } }))
    },
    [],
  )

  const closeOverlay = useCallback((name: OverlayName) => {
    setStates((prev) => ({ ...prev, [name]: { open: false, props: {} } }))
  }, [])

  return (
    <OverlayContext.Provider value={{ states, openOverlay, closeOverlay }}>
      {children}
    </OverlayContext.Provider>
  )
}
