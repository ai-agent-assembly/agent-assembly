import { useEffect, useState } from 'react'

/**
 * Light / dark theme support for the dashboard.
 *
 * The visual system is entirely token-driven (see src/styles.css): the active
 * theme is selected by a `data-theme` attribute on the document root, which
 * swaps the `:root[data-theme="dark"]` custom-property block. This module owns
 * resolving, applying, and persisting that choice.
 *
 * Resolution order on first load (no explicit user choice yet):
 *   1. a previously-saved preference in localStorage, else
 *   2. the operating-system setting (`prefers-color-scheme`).
 */

export type Theme = 'light' | 'dark'

export const THEME_STORAGE_KEY = 'aa-dashboard-theme'

function prefersDark(): boolean {
  return (
    typeof globalThis !== 'undefined' &&
    typeof globalThis.matchMedia === 'function' &&
    globalThis.matchMedia('(prefers-color-scheme: dark)').matches
  )
}

function readStored(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_STORAGE_KEY)
    return v === 'light' || v === 'dark' ? v : null
  } catch {
    return null
  }
}

/** Resolve the theme to use before/at first render. */
export function getInitialTheme(): Theme {
  return readStored() ?? (prefersDark() ? 'dark' : 'light')
}

/** Apply a theme to the document root (idempotent). */
export function applyTheme(theme: Theme): void {
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = theme
  }
}

export interface UseThemeResult {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
}

export function useTheme(): UseThemeResult {
  const [theme, setThemeState] = useState<Theme>(getInitialTheme)

  // Keep the document root in sync with the active theme.
  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  // Follow OS changes only while the user has NOT made an explicit choice.
  useEffect(() => {
    if (typeof globalThis === 'undefined' || typeof globalThis.matchMedia !== 'function') return
    const mq = globalThis.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => {
      if (readStored() === null) setThemeState(e.matches ? 'dark' : 'light')
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const persist = (next: Theme) => {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next)
    } catch {
      /* storage unavailable (private mode) — theme still applies for the session */
    }
    setThemeState(next)
  }

  return {
    theme,
    setTheme: persist,
    toggleTheme: () => persist(theme === 'dark' ? 'light' : 'dark'),
  }
}
