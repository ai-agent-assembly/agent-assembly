// Controlled-form state hook for the Policy Editor (AAASM-1370).
import { useCallback, useMemo, useState } from 'react'
import { defaultRule, nextRuleId } from './constants'
import type { PolicyDraft, RuleDraft } from './types'

export interface UseDraftResult {
  draft: PolicyDraft
  /** True when the live draft differs from the initial value (deep compare). */
  isDirty: boolean
  updateMeta: (patch: Partial<Omit<PolicyDraft, 'rules'>>) => void
  updateRule: (index: number, patch: Partial<RuleDraft>) => void
  addRule: () => void
  duplicateRule: (index: number) => void
  removeRule: (index: number) => void
  /** Reset back to the initial draft passed to the hook. */
  reset: () => void
}

/**
 * Form-state hook for editing a PolicyDraft. Dirty tracking is done by
 * comparing serialised JSON of the live draft vs. the initial draft — the
 * same approach the hi-fi prototype uses.
 */
export function useDraft(initial: PolicyDraft): UseDraftResult {
  const [draft, setDraft] = useState<PolicyDraft>(initial)
  const initialJson = useMemo(() => JSON.stringify(initial), [initial])
  const isDirty = JSON.stringify(draft) !== initialJson

  const updateMeta = useCallback(
    (patch: Partial<Omit<PolicyDraft, 'rules'>>) => {
      setDraft((d) => ({ ...d, ...patch }))
    },
    [],
  )

  const updateRule = useCallback((index: number, patch: Partial<RuleDraft>) => {
    setDraft((d) => ({
      ...d,
      rules: d.rules.map((r, i) => (i === index ? { ...r, ...patch } : r)),
    }))
  }, [])

  const addRule = useCallback(() => {
    setDraft((d) => ({ ...d, rules: [...d.rules, defaultRule()] }))
  }, [])

  const duplicateRule = useCallback((index: number) => {
    setDraft((d) => {
      const original = d.rules[index]
      if (!original) return d
      const copy: RuleDraft = { ...original, id: nextRuleId() }
      const next = [...d.rules]
      next.splice(index + 1, 0, copy)
      return { ...d, rules: next }
    })
  }, [])

  const removeRule = useCallback((index: number) => {
    setDraft((d) => ({ ...d, rules: d.rules.filter((_, i) => i !== index) }))
  }, [])

  const reset = useCallback(() => {
    setDraft(initial)
  }, [initial])

  return { draft, isDirty, updateMeta, updateRule, addRule, duplicateRule, removeRule, reset }
}
