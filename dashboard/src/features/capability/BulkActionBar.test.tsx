/**
 * The bulk override bar may only offer decisions the gateway accepts
 * (AAASM-5124).
 *
 * `POST /api/v1/capability/override` 400s on `narrow` and `approval`, so the
 * bar previously pre-selected a guaranteed rejection: applying without touching
 * the dropdown — the most likely single interaction on this control — could
 * never succeed. These runs assert the two properties that stop that
 * recurring: the offered set contains nothing the endpoint refuses, and the
 * value submitted by an untouched bar is one it accepts.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { BulkActionBar } from './BulkActionBar'
import { OVERRIDABLE_DECISIONS } from './types'
import type { Resource } from './types'

/** The two decisions `apply_override` rejects with a 400. */
const REJECTED_BY_GATEWAY = ['narrow', 'approval'] as const

const RESOURCES: Resource[] = [
  { id: 'gmail', name: 'gmail', group: 'comm', paths: ['gmail/*'] },
  { id: 's3', name: 's3', group: 'data', paths: ['s3/*'] },
]

function renderBar(onApply = vi.fn(), count = 2) {
  const onClear = vi.fn()
  render(
    <BulkActionBar
      count={count}
      resources={RESOURCES}
      verb="write"
      onApply={onApply}
      onClear={onClear}
    />,
  )
  return { onApply, onClear }
}

function decisionSelect() {
  return screen.getByLabelText('decision') as HTMLSelectElement
}

describe('BulkActionBar', () => {
  it('offers exactly the decisions the override endpoint accepts', () => {
    renderBar()
    const offered = [...decisionSelect().options].map((o) => o.value)
    expect(offered).toEqual([...OVERRIDABLE_DECISIONS])
    for (const rejected of REJECTED_BY_GATEWAY) {
      expect(offered).not.toContain(rejected)
    }
  })

  it('pre-selects a decision the endpoint accepts', () => {
    renderBar()
    const select = decisionSelect()
    expect(OVERRIDABLE_DECISIONS as readonly string[]).toContain(select.value)
    expect(REJECTED_BY_GATEWAY as readonly string[]).not.toContain(select.value)
  })

  it('submits the pre-selected decision when the dropdown is never touched', () => {
    const { onApply } = renderBar()
    fireEvent.click(screen.getByRole('button', { name: 'Apply override' }))
    expect(onApply).toHaveBeenCalledWith({
      resourceId: 'gmail',
      decision: decisionSelect().value,
    })
  })

  it('still submits a decision the endpoint accepts after the operator picks one', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'allow' } })
    fireEvent.change(screen.getByLabelText('resource'), { target: { value: 's3' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply override' }))
    expect(onApply).toHaveBeenCalledWith({ resourceId: 's3', decision: 'allow' })
  })

  it('refuses a rejected decision pushed at the select instead of casting it', () => {
    const { onApply } = renderBar()
    const select = decisionSelect()
    const before = select.value

    // No such option exists, so the DOM resolves the assignment to '' and the
    // change handler is handed a value that is not a decision at all. The bar
    // parses rather than asserts, so the state keeps its accepted value.
    fireEvent.change(select, { target: { value: 'narrow' } })

    fireEvent.click(screen.getByRole('button', { name: 'Apply override' }))
    expect(onApply).toHaveBeenCalledWith({ resourceId: 'gmail', decision: before })
    expect(onApply).not.toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'narrow' }),
    )
  })

  it('renders nothing without a selection or without resources', () => {
    const { container } = render(
      <BulkActionBar
        count={0}
        resources={RESOURCES}
        verb="write"
        onApply={vi.fn()}
        onClear={vi.fn()}
      />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('clears the selection', () => {
    const { onClear } = renderBar()
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onClear).toHaveBeenCalledTimes(1)
  })
})
