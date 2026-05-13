import { useContext } from 'react'
import { OverlayContext, type OverlayName } from './OverlayContext'

/**
 * Access the named overlay surface from any descendant of `<OverlayProvider>`.
 * Returns the current `open` flag, the `props` last passed to `openOverlay`,
 * and a pair of action callbacks bound to this overlay name.
 */
export function useOverlay(name: OverlayName) {
  const ctx = useContext(OverlayContext)
  if (!ctx) throw new Error('useOverlay must be used within an OverlayProvider')
  const state = ctx.states[name]
  return {
    open: state.open,
    props: state.props,
    openOverlay: (props?: Record<string, unknown>) => ctx.openOverlay(name, props),
    closeOverlay: () => ctx.closeOverlay(name),
  }
}
