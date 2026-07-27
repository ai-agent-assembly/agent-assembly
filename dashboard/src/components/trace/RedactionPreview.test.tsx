import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { absent, isAbsent, isKnown, known } from '../../lib/truthfulness'
import { RedactionPreview } from './RedactionPreview'
import { previewJson } from './previewJson'

const PAYLOAD = known({
  action: 'process_refund',
  amount: 250,
  user_id: 4521,
  notes: 'manual review',
})

const REDACTED = (...fields: string[]) => known<readonly string[]>(fields)

describe('RedactionPreview', () => {
  it('renders █ blocks for redacted fields and never leaks the real value', () => {
    render(<RedactionPreview payload={PAYLOAD} redactedFields={REDACTED('user_id')} />)
    const block = screen.getByTestId('redaction-block')
    expect(block.textContent).toMatch(/^█+$/)
    // The real value must not appear anywhere in the rendered preview.
    expect(screen.getByTestId('redaction-preview-body').textContent).not.toContain('4521')
  })

  it('shows non-redacted values verbatim', () => {
    render(<RedactionPreview payload={PAYLOAD} redactedFields={REDACTED('user_id')} />)
    const body = screen.getByTestId('redaction-preview-body')
    expect(body).toHaveTextContent('process_refund')
    expect(body).toHaveTextContent('250')
  })

  it('lists each redacted field as a tag under the preview', () => {
    render(<RedactionPreview payload={PAYLOAD} redactedFields={REDACTED('user_id', 'notes')} />)
    const tags = screen.getByTestId('redaction-tags')
    expect(tags).toHaveTextContent('redacted')
    expect(tags).toHaveTextContent('user_id')
    expect(tags).toHaveTextContent('notes')
  })

  it('omits the tag list when nothing is redacted', () => {
    render(<RedactionPreview payload={PAYLOAD} />)
    expect(screen.queryByTestId('redaction-tags')).not.toBeInTheDocument()
    expect(screen.queryByTestId('redaction-block')).not.toBeInTheDocument()
  })

  it('omits the tag list when the redaction field itself is unavailable', () => {
    // The production shape: `TraceSpan` has no redaction field at all, so there
    // is nothing to tag — and an absent list must not render an empty
    // "redacted" header implying a clean scrub.
    render(
      <RedactionPreview
        payload={PAYLOAD}
        redactedFields={absent<readonly string[]>('not-supported', 'no wire field')}
      />,
    )
    expect(screen.queryByTestId('redaction-tags')).not.toBeInTheDocument()
  })

  it('shows the payload kind in the header when provided', () => {
    render(<RedactionPreview payload={PAYLOAD} kind="policy_violation" />)
    expect(screen.getByTestId('redaction-preview')).toHaveTextContent('policy_violation')
  })
})

/**
 * AAASM-5165. `JSON.stringify(payload, null, 2) ?? 'null'` printed the literal
 * four-character string `null` into the preview body, so an operator read "the
 * recorded payload was null" when in fact nothing had been recorded at all.
 *
 * Both routes to that string are covered below, plus the case the whole trace
 * surface now hits in production — an absent payload — because after AAASM-5109
 * `payload` has no wire source and is `not-supported` on every single event.
 * Without this guard the string `null` would be the *only* thing the preview
 * ever rendered.
 */
describe('the literal string "null" never reaches the preview body', () => {
  it.each([
    ['an absent payload (the production shape)', absent<unknown>('not-supported', 'no wire field')],
    ['a payload recorded as JSON null', known<unknown>(null)],
    ['a payload recorded as undefined', known<unknown>(undefined)],
  ])('renders the absence instead of the word null for %s', (_label, payload) => {
    render(<RedactionPreview payload={payload} />)

    const body = screen.getByTestId('redaction-preview-body')
    expect(body.textContent).not.toContain('null')
    expect(screen.getByTestId('redaction-preview-absent')).toBeInTheDocument()
    expect(body).toHaveTextContent('no payload recorded')
  })

  it('carries the absence state through to the marker', () => {
    render(
      <RedactionPreview payload={absent<unknown>('not-supported', 'TraceSpan has no payload field')} />,
    )
    expect(screen.getByTestId('redaction-preview-absent')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
  })
})

describe('previewJson', () => {
  it('formats a real payload as indented JSON', () => {
    const text = previewJson(known({ a: 1 }))
    expect(isKnown(text) && text.value).toBe('{\n  "a": 1\n}')
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
  ])('reports a %s payload as an absence rather than as content', (_label, value) => {
    // `JSON.stringify(null)` returns the *string* "null" and
    // `JSON.stringify(undefined)` returns the *value* undefined — different
    // routes, same wrong pixel, so both are pinned.
    const text = previewJson(known<unknown>(value))
    expect(isAbsent(text)).toBe(true)
    expect(isKnown(text)).toBe(false)
  })

  it('reports a value with no JSON representation as an absence', () => {
    // `stringify` signals this by returning undefined rather than throwing.
    const text = previewJson(known<unknown>(() => 'not serialisable'))
    expect(isAbsent(text) && text.state).toBe('unknown')
  })

  it('propagates an existing absence with its state intact', () => {
    const text = previewJson(absent<unknown>('not-supported', 'TraceSpan has no payload field'))
    expect(isAbsent(text) && text.state).toBe('not-supported')
    expect(isAbsent(text) && text.detail).toBe('TraceSpan has no payload field')
  })
})
