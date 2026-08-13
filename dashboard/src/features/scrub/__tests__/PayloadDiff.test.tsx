import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { PayloadDiff } from '../PayloadDiff'
import { BUILT_IN_DETECTORS } from '../detectors'
import type { ScrubToken } from '../types'

const AWS = BUILT_IN_DETECTORS.find((d) => d.id === 'AwsAccessKey')!
const EMAIL = BUILT_IN_DETECTORS.find((d) => d.id === 'EmailAddress')!

const TOKENS: ScrubToken[] = [
  { kind: 'plain', text: 'key=' },
  { kind: 'match', text: 'AKIAIOSFODNN7EXAMPLE', detector: AWS },
  { kind: 'plain', text: ' for ' },
  { kind: 'match', text: 'a@b.com', detector: EMAIL },
]

const renderDiff = (overrides: Partial<React.ComponentProps<typeof PayloadDiff>> = {}) =>
  render(
    <PayloadDiff
      payload="key=AKIAIOSFODNN7EXAMPLE for a@b.com"
      onPayloadChange={vi.fn()}
      tokens={TOKENS}
      detectors={BUILT_IN_DETECTORS}
      matchCounts={{ AwsAccessKey: 1, EmailAddress: 1 }}
      {...overrides}
    />,
  )

describe('PayloadDiff', () => {
  it('counts matches as "in sample", not as secrets detected in traffic', () => {
    renderDiff()
    expect(screen.getByTestId('scrub-diff-detected-count')).toHaveTextContent(
      '2 matched in sample',
    )
  })

  it('never declares the preview output safe to forward', () => {
    // The scrubbed pane carried an unconditional green "safe to forward" chip
    // over text nothing had scanned — an unmeasured input rendered as a
    // reassuring outcome (AAASM-5112's rule).
    renderDiff()
    const chip = screen.getByTestId('scrub-diff-scope')
    expect(chip).toHaveTextContent('approximation')
    expect(chip).not.toHaveTextContent(/safe/i)
    expect(chip.className).not.toContain('--ok')
    // The only surviving mention of forwarding is the caveat's denial of it.
    expect(screen.getByTestId('scrub-diff-caveat')).toHaveTextContent(
      'not a verdict that a payload is safe to forward',
    )
  })

  it('states in visible text that this is a local approximation, and what it misses', () => {
    renderDiff()
    const caveat = screen.getByTestId('scrub-diff-caveat')
    expect(caveat).toHaveTextContent(/approximates/i)
    expect(caveat).toHaveTextContent('GenericHighEntropy')
    expect(caveat).toHaveTextContent('Custom')
  })

  it('renders matches on the raw side', () => {
    renderDiff()
    const raw = screen.getByTestId('scrub-diff-preview-raw')
    expect(raw).toHaveTextContent('AKIAIOSFODNN7EXAMPLE')
    expect(raw).toHaveTextContent('a@b.com')
  })

  it('renders the gateway’s real labels on the scrubbed side, not the raw values', () => {
    renderDiff()
    const scrubbed = screen.getByTestId('scrub-diff-preview-scrubbed')
    expect(scrubbed).toHaveTextContent('[REDACTED:AwsAccessKey]')
    expect(scrubbed).toHaveTextContent('[REDACTED:EmailAddress]')
    expect(scrubbed).not.toHaveTextContent('AKIAIOSFODNN7EXAMPLE')
    expect(scrubbed).not.toHaveTextContent('a@b.com')
    // Labels the previous fixture taught that aa-security never emits.
    expect(scrubbed).not.toHaveTextContent('[REDACTED:AWS_KEY]')
    expect(scrubbed).not.toHaveTextContent('[REDACTED:EMAIL]')
  })

  it('groups matches by detector in the summary list', () => {
    renderDiff()
    expect(screen.getByTestId('scrub-diff-summary-AwsAccessKey')).toHaveTextContent('×1')
    expect(screen.getByTestId('scrub-diff-summary-EmailAddress')).toHaveTextContent('×1')
  })

  it('says no approximable detector matched, rather than declaring the payload clean', () => {
    renderDiff({ tokens: [{ kind: 'plain', text: 'hello' }], matchCounts: {} })
    const empty = screen.getByTestId('scrub-diff-summary-empty')
    expect(empty).toHaveTextContent('no detector this preview can approximate matched')
    expect(empty).not.toHaveTextContent(/safe|clean|no secrets/i)
  })

  it('emits onPayloadChange when the textarea is edited', () => {
    const onChange = vi.fn()
    renderDiff({ onPayloadChange: onChange })
    fireEvent.change(screen.getByTestId('scrub-diff-textarea'), {
      target: { value: 'hi there' },
    })
    expect(onChange).toHaveBeenCalledWith('hi there')
  })
})
