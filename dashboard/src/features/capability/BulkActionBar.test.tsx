/**
 * The bulk override bar must not write on an unconsidered click (AAASM-5124),
 * and must not claim an enforcement change it did not make (AAASM-5178).
 *
 * Two earlier revisions of this bar failed in opposite directions. The first
 * pre-selected `narrow`, which the gateway 400s — so the likeliest single
 * interaction was a guaranteed failure. The second pre-selected `deny` to fix
 * that, which made the same unconsidered click a *successful* bulk write across
 * every selected agent with no undo in the UI. These runs pin the third answer:
 * no default at all, an explicit confirmation naming what is about to happen,
 * and language that says the write is an annotation rather than an enforcement
 * change.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { BulkActionBar, DISPLAY_ONLY_NOTE, NO_DECISION_TITLE } from './BulkActionBar'
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

function applyButton() {
  return screen.getByRole('button', { name: 'Record display-only override' })
}

describe('BulkActionBar', () => {
  it('starts with no decision selected', () => {
    renderBar()
    expect(decisionSelect().value).toBe('')
    for (const accepted of OVERRIDABLE_DECISIONS) {
      expect(decisionSelect().value).not.toBe(accepted)
    }
  })

  it('disables the apply control until a decision is chosen, with the reason on it', () => {
    renderBar()
    expect(applyButton()).toBeDisabled()
    expect(applyButton()).toHaveAttribute('title', NO_DECISION_TITLE)

    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })

    expect(applyButton()).toBeEnabled()
    expect(applyButton()).not.toHaveAttribute('title')
  })

  it('does not write when the bar is applied without a decision', () => {
    const { onApply } = renderBar()
    fireEvent.click(applyButton())
    expect(onApply).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument()
  })

  it('does not write until the confirmation is accepted', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    fireEvent.click(applyButton())

    // Pressing apply opens the confirmation and nothing else — the write is
    // still one deliberate step away.
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
    expect(onApply).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(onApply).toHaveBeenCalledWith({ resourceId: 'gmail', decision: 'deny' })
  })

  it('states the decision and how many agents it affects in the confirmation', () => {
    renderBar(vi.fn(), 3)
    fireEvent.change(decisionSelect(), { target: { value: 'allow' } })
    fireEvent.click(applyButton())

    const confirm = screen.getByLabelText('confirm override')
    expect(confirm).toHaveTextContent('allow')
    expect(confirm).toHaveTextContent('3 agents')
    expect(confirm).toHaveTextContent('write')
    expect(confirm).toHaveTextContent('gmail')
  })

  it('singularises the affected-agent count for a one-agent selection', () => {
    renderBar(vi.fn(), 1)
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    fireEvent.click(applyButton())
    expect(screen.getByLabelText('confirm override')).toHaveTextContent('1 agent?')
  })

  it('says the write is an annotation, not an enforcement change', () => {
    renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    fireEvent.click(applyButton())

    // AAASM-5178: the override store has never fed enforcement, so neither the
    // control nor the confirmation may read as though a gateway decision moved.
    expect(screen.getByText(DISPLAY_ONLY_NOTE)).toBeInTheDocument()
    expect(DISPLAY_ONLY_NOTE).toMatch(/does not change what the gateway enforces/)
    expect(applyButton()).toHaveTextContent(/display-only/i)
  })

  it('cancels without writing, and re-arms for a fresh confirmation', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    fireEvent.click(applyButton())
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(onApply).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument()
    expect(applyButton()).toBeEnabled()
  })

  it('retracts a pending confirmation when the decision changes under it', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    fireEvent.click(applyButton())

    // The confirmation names a decision; changing it would leave that text
    // describing a write different from the one Confirm would perform.
    fireEvent.change(decisionSelect(), { target: { value: 'allow' } })
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument()
    expect(onApply).not.toHaveBeenCalled()
  })

  it('retracts a pending confirmation when the resource changes under it', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    fireEvent.click(applyButton())
    fireEvent.change(screen.getByLabelText('resource'), { target: { value: 's3' } })

    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument()
    expect(onApply).not.toHaveBeenCalled()
  })

  it('offers exactly the decisions the override endpoint accepts', () => {
    renderBar()
    const offered = [...decisionSelect().options].map((o) => o.value)
    // The leading '' is the no-selection placeholder, not a decision.
    expect(offered).toEqual(['', ...OVERRIDABLE_DECISIONS])
    for (const rejected of REJECTED_BY_GATEWAY) {
      expect(offered).not.toContain(rejected)
    }
  })

  it('submits the resource and decision the operator actually chose', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'allow' } })
    fireEvent.change(screen.getByLabelText('resource'), { target: { value: 's3' } })
    fireEvent.click(applyButton())
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(onApply).toHaveBeenCalledWith({ resourceId: 's3', decision: 'allow' })
  })

  it('falls back to no-selection when a rejected decision is pushed at the select', () => {
    const { onApply } = renderBar()
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })

    // No such option exists, so the DOM resolves the assignment to '' and the
    // change handler is handed a value that is not a decision at all. The bar
    // parses rather than asserts, and an unparseable value disarms the control
    // rather than leaving the previous decision armed behind it.
    fireEvent.change(decisionSelect(), { target: { value: 'narrow' } })

    expect(decisionSelect().value).toBe('')
    expect(applyButton()).toBeDisabled()
    fireEvent.click(applyButton())
    expect(onApply).not.toHaveBeenCalled()
  })

  it('names a resource by its id when the projection stops carrying it', () => {
    // A refetch can drop the selected resource while the selection survives, so
    // the confirmation falls back to the raw id rather than naming nothing at
    // all — a confirmation with a blank subject is not a confirmation.
    const { rerender } = render(
      <BulkActionBar
        count={2}
        resources={RESOURCES}
        verb="write"
        onApply={vi.fn()}
        onClear={vi.fn()}
      />,
    )
    fireEvent.change(decisionSelect(), { target: { value: 'deny' } })
    rerender(
      <BulkActionBar
        count={2}
        resources={[{ id: 'vault', name: 'vault', group: 'infra', paths: ['vault/*'] }]}
        verb="write"
        onApply={vi.fn()}
        onClear={vi.fn()}
      />,
    )
    fireEvent.click(applyButton())
    expect(screen.getByLabelText('confirm override')).toHaveTextContent('gmail')
  })

  it('renders nothing without a selection', () => {
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

  it('renders nothing when the projection carries no resources', () => {
    const { container } = render(
      <BulkActionBar count={2} resources={[]} verb="write" onApply={vi.fn()} onClear={vi.fn()} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('clears the selection', () => {
    const { onClear } = renderBar()
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onClear).toHaveBeenCalledTimes(1)
  })
})
