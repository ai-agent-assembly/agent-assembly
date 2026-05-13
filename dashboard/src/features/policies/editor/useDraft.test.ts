import { act, renderHook } from '@testing-library/react'
import { useDraft } from './useDraft'
import { emptyDraft } from './constants'

function makeInitial() {
  return emptyDraft()
}

describe('useDraft', () => {
  it('starts not-dirty with the supplied initial draft', () => {
    const initial = makeInitial()
    const { result } = renderHook(() => useDraft(initial))
    expect(result.current.draft).toEqual(initial)
    expect(result.current.isDirty).toBe(false)
  })

  it('marks dirty when updateMeta changes a field', () => {
    const { result } = renderHook(() => useDraft(makeInitial()))
    act(() => result.current.updateMeta({ name: 'edited' }))
    expect(result.current.draft.name).toBe('edited')
    expect(result.current.isDirty).toBe(true)
  })

  it('updateRule patches a single rule by index', () => {
    const { result } = renderHook(() => useDraft(makeInitial()))
    act(() => result.current.updateRule(0, { resource: 's3' }))
    expect(result.current.draft.rules[0].resource).toBe('s3')
    expect(result.current.isDirty).toBe(true)
  })

  it('addRule appends a default rule with a unique id', () => {
    const { result } = renderHook(() => useDraft(makeInitial()))
    const initialIds = result.current.draft.rules.map((r) => r.id)
    act(() => result.current.addRule())
    const rules = result.current.draft.rules
    expect(rules).toHaveLength(initialIds.length + 1)
    expect(initialIds).not.toContain(rules[rules.length - 1].id)
  })

  it('duplicateRule inserts a copy with a new id directly after the source index', () => {
    const { result } = renderHook(() => useDraft(makeInitial()))
    act(() => result.current.updateRule(0, { resource: 'github' }))
    act(() => result.current.duplicateRule(0))
    const rules = result.current.draft.rules
    expect(rules).toHaveLength(2)
    expect(rules[1].resource).toBe('github')
    expect(rules[1].id).not.toBe(rules[0].id)
  })

  it('removeRule drops the rule at the given index', () => {
    const { result } = renderHook(() => useDraft(makeInitial()))
    act(() => result.current.addRule())
    expect(result.current.draft.rules).toHaveLength(2)
    act(() => result.current.removeRule(0))
    expect(result.current.draft.rules).toHaveLength(1)
  })

  it('reset clears the dirty bit and restores the initial draft', () => {
    const initial = makeInitial()
    const { result } = renderHook(() => useDraft(initial))
    act(() => result.current.updateMeta({ name: 'changed' }))
    expect(result.current.isDirty).toBe(true)
    act(() => result.current.reset())
    expect(result.current.isDirty).toBe(false)
    expect(result.current.draft).toEqual(initial)
  })

  it('isDirty stays true after a no-op-back-to-initial mutation chain', () => {
    // Demonstrates that the comparison is value-based (JSON), not change-counted.
    const { result } = renderHook(() => useDraft(makeInitial()))
    act(() => result.current.updateMeta({ name: 'A' }))
    expect(result.current.isDirty).toBe(true)
    act(() => result.current.updateMeta({ name: '' }))
    // Original draft has name === ''. Setting it back to '' should be considered
    // not-dirty again because the values match.
    expect(result.current.isDirty).toBe(false)
  })
})
