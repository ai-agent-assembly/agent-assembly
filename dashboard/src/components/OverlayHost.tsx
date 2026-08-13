import { useEffect, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import type { OverlayName } from './OverlayContext'
import { useOverlay } from './useOverlay'
import './OverlayHost.css'

interface OverlayHostProps {
  /** Named overlay slot registered in OVERLAY_NAMES. */
  name: OverlayName
  /**
   * Optional interceptor for dismiss attempts (Esc key, backdrop click).
   * When provided, the host calls this instead of `closeOverlay` directly,
   * letting callers prompt for confirmation (e.g. an unsaved-changes guard
   * in the Policy Editor). The caller is responsible for invoking
   * `closeOverlay()` once it has decided to dismiss.
   */
  onRequestClose?: () => void
  children: ReactNode
}

/**
 * Renders `children` into the AppShell-level `<div data-overlay={name}>` mount
 * point as a full-screen overlay, gated by the `useOverlay(name).open` flag.
 * No effect when the overlay is closed or its mount point is missing.
 */
export function OverlayHost({ name, onRequestClose, children }: OverlayHostProps) {
  const { open, closeOverlay } = useOverlay(name)

  useEffect(() => {
    if (!open) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        const dismiss = onRequestClose ?? closeOverlay
        dismiss()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [open, onRequestClose, closeOverlay])

  if (!open) return null

  const target =
    typeof document === 'undefined'
      ? null
      : document.querySelector(`[data-overlay="${name}"]`)
  if (!target) return null

  const handleBackdropClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target !== e.currentTarget) return
    const dismiss = onRequestClose ?? closeOverlay
    dismiss()
  }

  // Dismissal is driven by Escape via the document-level listener above; the
  // backdrop key handler exists to satisfy the click/keyboard parity rule and
  // mirrors the backdrop click for keyboard users who focus the backdrop.
  const handleBackdropKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.target !== e.currentTarget) return
    if (e.key !== 'Enter' && e.key !== ' ') return
    e.preventDefault()
    const dismiss = onRequestClose ?? closeOverlay
    dismiss()
  }

  return createPortal(
    <div
      className="overlay-backdrop"
      data-testid={`overlay-${name}`}
      onClick={handleBackdropClick}
      onKeyDown={handleBackdropKeyDown}
      role="button"
      tabIndex={-1}
      aria-label="Close overlay"
    >
      <div className="overlay-container" role="dialog" aria-modal="true">
        {children}
      </div>
    </div>,
    target,
  )
}
