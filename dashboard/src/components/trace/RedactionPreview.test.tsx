import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { RedactionPreview } from './RedactionPreview'

const PAYLOAD = {
  action: 'process_refund',
  amount: 250,
  user_id: 4521,
  notes: 'manual review',
}

describe('RedactionPreview', () => {
  it('renders █ blocks for redacted fields and never leaks the real value', () => {
    render(<RedactionPreview payload={PAYLOAD} redactedFields={['user_id']} />)
    const block = screen.getByTestId('redaction-block')
    expect(block.textContent).toMatch(/^█+$/)
    // The real value must not appear anywhere in the rendered preview.
    expect(screen.getByTestId('redaction-preview-body').textContent).not.toContain('4521')
  })

  it('shows non-redacted values verbatim', () => {
    render(<RedactionPreview payload={PAYLOAD} redactedFields={['user_id']} />)
    const body = screen.getByTestId('redaction-preview-body')
    expect(body).toHaveTextContent('process_refund')
    expect(body).toHaveTextContent('250')
  })

  it('lists each redacted field as a tag under the preview', () => {
    render(<RedactionPreview payload={PAYLOAD} redactedFields={['user_id', 'notes']} />)
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

  it('shows the payload kind in the header when provided', () => {
    render(<RedactionPreview payload={PAYLOAD} kind="policy_violation" />)
    expect(screen.getByTestId('redaction-preview')).toHaveTextContent('policy_violation')
  })
})
