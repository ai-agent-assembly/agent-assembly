import { createContext } from 'react'

/**
 * Named overlay surfaces exposed at the AppShell level.
 * Each entry corresponds to a `<div data-overlay="…" />` portal target
 * rendered by `AppShell` so pages can trigger global panels/drawers
 * without re-mounting them.
 */
export const OVERLAY_NAMES = ['tweaks', 'alerts', 'trace', 'identity', 'teams'] as const

export type OverlayName = (typeof OVERLAY_NAMES)[number]

export interface OverlayState {
  /** Whether the overlay is currently open. */
  open: boolean
  /** Arbitrary props handed to the (future) overlay component. */
  props: Record<string, unknown>
}

export interface OverlayContextValue {
  states: Record<OverlayName, OverlayState>
  openOverlay: (name: OverlayName, props?: Record<string, unknown>) => void
  closeOverlay: (name: OverlayName) => void
}

export const OverlayContext = createContext<OverlayContextValue | null>(null)
