import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { getInitialTheme, applyTheme, useTheme, THEME_STORAGE_KEY } from './useTheme'

function mockMatchMedia(matchesDark: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query.includes('dark') ? matchesDark : false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }))
}

beforeEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
})

describe('theme resolution', () => {
  it('falls back to the OS preference when nothing is stored', () => {
    mockMatchMedia(true)
    expect(getInitialTheme()).toBe('dark')
    mockMatchMedia(false)
    expect(getInitialTheme()).toBe('light')
  })

  it('honors a stored preference over the OS setting', () => {
    mockMatchMedia(true) // OS is dark…
    localStorage.setItem(THEME_STORAGE_KEY, 'light')
    expect(getInitialTheme()).toBe('light') // …but the saved choice wins
  })

  it('applyTheme sets data-theme on the document root', () => {
    applyTheme('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })
})

describe('useTheme', () => {
  it('toggles, persists the choice, and updates the document root', () => {
    mockMatchMedia(false)
    const { result } = renderHook(() => useTheme())

    expect(result.current.theme).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')

    act(() => result.current.toggleTheme())

    expect(result.current.theme).toBe('dark')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })
})
