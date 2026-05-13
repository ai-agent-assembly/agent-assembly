import { useCallback, useState } from 'react'
import type { GeneratedApiKey } from './types'

/**
 * Holds the once-only generated key payload (id, prefix, **secret**)
 * in local component state. Intentionally not backed by React Query —
 * the secret must not survive a cache scan or a tab restore.
 *
 * The reveal lifecycle:
 *   1. `reveal(secret)`  — caller stores the just-generated payload.
 *   2. `markCopied()`    — operator hit the copy button.
 *   3. `clear()`         — modal closes (autoclose or manual) and the
 *                          secret is wiped from memory.
 */
export interface RevealOnceState {
  current: GeneratedApiKey | null
  copied: boolean
  reveal: (key: GeneratedApiKey) => void
  markCopied: () => void
  clear: () => void
}

export function useRevealOnceState(): RevealOnceState {
  const [current, setCurrent] = useState<GeneratedApiKey | null>(null)
  const [copied, setCopied] = useState(false)

  const reveal = useCallback((key: GeneratedApiKey) => {
    setCurrent(key)
    setCopied(false)
  }, [])

  const markCopied = useCallback(() => {
    setCopied(true)
  }, [])

  const clear = useCallback(() => {
    setCurrent(null)
    setCopied(false)
  }, [])

  return { current, copied, reveal, markCopied, clear }
}
