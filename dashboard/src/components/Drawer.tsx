import { useEffect, useRef, type MouseEvent, type ReactNode } from 'react'
import './Drawer.css'

interface DrawerProps {
  /** When `true`, drawer + scrim render; when `false`, nothing is rendered. */
  open: boolean
  /** Fires on ESC keypress, scrim click, or close-button click. */
  onClose: () => void
  /** Drawer body. Drawer is unstyled inside; the caller supplies its layout. */
  children: ReactNode
  /** Accessible label for the dialog. */
  ariaLabel?: string
}

/**
 * Right-side modal drawer matching `design/v1/styles.css` `.drawer`.
 *
 * Closes on:
 *   * `Escape` keypress (handled at `document` level so focus inside the
 *     drawer doesn't prevent the shortcut),
 *   * click on the scrim (the surrounding dimmed area), or
 *   * click on the close button rendered in the drawer head by the caller.
 *
 * The component is presentational only — opening/closing the drawer is the
 * caller's responsibility (typically by mounting / unmounting at a routed
 * URL). No focus trap; v1 relies on the underlying page being inert behind
 * the scrim.
 */
export function Drawer({ open, onClose, children, ariaLabel }: DrawerProps) {
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  useEffect(() => {
    if (!open) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseRef.current()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [open])

  if (!open) return null

  function handleScrimClick(e: MouseEvent<HTMLDivElement>) {
    // Only the scrim itself should dismiss; clicks bubbling up from the panel
    // (the drawer body) must be ignored.
    if (e.target === e.currentTarget) onClose()
  }

  return (
    <div
      className="drawer-scrim"
      data-testid="drawer-scrim"
      onClick={handleScrimClick}
      role="presentation"
    >
      <aside
        className="drawer-panel"
        data-testid="drawer-panel"
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel}
      >
        {children}
      </aside>
    </div>
  )
}
