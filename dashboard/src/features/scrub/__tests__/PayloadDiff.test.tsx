import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PayloadDiff } from '../PayloadDiff'
import type { ScrubPattern, ScrubToken } from '../types'

const AWS: ScrubPattern = {
  id: 'AWS_KEY',
  name: 'AWS access key',
  regex: 'AKIA[0-9A-Z]{16}',
  example: 'AKIAIOSFODNN7EXAMPLE',
  replace: '[REDACTED:AWS_KEY]',
  severity: 'critical',
  hits24h: 1,
  enabled: true,
}

const EMAIL: ScrubPattern = {
  ...AWS,
  id: 'EMAIL_PII',
  name: 'Email',
  regex: '[a-z]+@[a-z]+',
  example: 'a@b',
  replace: '[REDACTED:EMAIL]',
  severity: 'medium',
}

const TOKENS: ScrubToken[] = [
  { kind: 'plain', text: 'key=' },
  { kind: 'match', text: 'AKIAABCDEFGHIJKLMNOP', pattern: AWS },
  { kind: 'plain', text: ' for ' },
  { kind: 'match', text: 'a@b', pattern: EMAIL },
]

describe('PayloadDiff', () => {
  it('reflects the detected match count in the header chip', () => {
    render(
      <PayloadDiff
        payload="key=AKIAABCDEFGHIJKLMNOP for a@b"
        onPayloadChange={vi.fn()}
        tokens={TOKENS}
        patterns={[AWS, EMAIL]}
        matchCounts={{ AWS_KEY: 1, EMAIL_PII: 1 }}
      />,
    )
    expect(screen.getByTestId('scrub-diff-detected-count')).toHaveTextContent(
      '2 secrets detected',
    )
  })

  it('renders matches as struck-through text on the raw side', () => {
    render(
      <PayloadDiff
        payload="key=AKIAABCDEFGHIJKLMNOP for a@b"
        onPayloadChange={vi.fn()}
        tokens={TOKENS}
        patterns={[AWS, EMAIL]}
        matchCounts={{ AWS_KEY: 1, EMAIL_PII: 1 }}
      />,
    )
    const raw = screen.getByTestId('scrub-diff-preview-raw')
    expect(raw).toHaveTextContent('AKIAABCDEFGHIJKLMNOP')
    expect(raw).toHaveTextContent('a@b')
  })

  it('renders [REDACTED:XXX] placeholders on the scrubbed side, not the raw values', () => {
    render(
      <PayloadDiff
        payload="key=AKIAABCDEFGHIJKLMNOP for a@b"
        onPayloadChange={vi.fn()}
        tokens={TOKENS}
        patterns={[AWS, EMAIL]}
        matchCounts={{ AWS_KEY: 1, EMAIL_PII: 1 }}
      />,
    )
    const scrubbed = screen.getByTestId('scrub-diff-preview-scrubbed')
    expect(scrubbed).toHaveTextContent('[REDACTED:AWS_KEY]')
    expect(scrubbed).toHaveTextContent('[REDACTED:EMAIL]')
    expect(scrubbed).not.toHaveTextContent('AKIAABCDEFGHIJKLMNOP')
    expect(scrubbed).not.toHaveTextContent('a@b')
  })

  it('groups detected matches by pattern in the summary list', () => {
    render(
      <PayloadDiff
        payload="x"
        onPayloadChange={vi.fn()}
        tokens={TOKENS}
        patterns={[AWS, EMAIL]}
        matchCounts={{ AWS_KEY: 1, EMAIL_PII: 1 }}
      />,
    )
    expect(screen.getByTestId('scrub-diff-summary-AWS_KEY')).toHaveTextContent('×1')
    expect(screen.getByTestId('scrub-diff-summary-EMAIL_PII')).toHaveTextContent('×1')
  })

  it('shows the empty summary when there are no matches', () => {
    render(
      <PayloadDiff
        payload="hello"
        onPayloadChange={vi.fn()}
        tokens={[{ kind: 'plain', text: 'hello' }]}
        patterns={[AWS]}
        matchCounts={{}}
      />,
    )
    expect(screen.getByTestId('scrub-diff-summary-empty')).toBeInTheDocument()
  })

  it('emits onPayloadChange when the textarea is edited', () => {
    const onChange = vi.fn()
    render(
      <PayloadDiff
        payload="hello"
        onPayloadChange={onChange}
        tokens={[{ kind: 'plain', text: 'hello' }]}
        patterns={[AWS]}
        matchCounts={{}}
      />,
    )
    fireEvent.change(screen.getByTestId('scrub-diff-textarea'), {
      target: { value: 'hi there' },
    })
    expect(onChange).toHaveBeenCalledWith('hi there')
  })
})
