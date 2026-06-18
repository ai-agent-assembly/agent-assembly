import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Step3IssueIdentity } from './Step3IssueIdentity'
import { EMPTY_STATE, type WizardState } from '../types'

const ISSUED_STATE: WizardState = {
  ...EMPTY_STATE,
  identity: {
    did: 'did:aa:deadbeef',
    alg: 'Ed25519',
    fingerprint: 'AA:BB:CC',
    issuedAt: '2026-05-01 10:00:00Z',
  },
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.runOnlyPendingTimers()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('Step3IssueIdentity', () => {
  it('renders the generate button in the idle phase', () => {
    render(<Step3IssueIdentity state={EMPTY_STATE} onIssued={vi.fn()} />)
    expect(screen.getByTestId('onboarding-identity-generate')).toBeInTheDocument()
  })

  it('shows the issued identity immediately when state already has one', () => {
    render(<Step3IssueIdentity state={ISSUED_STATE} onIssued={vi.fn()} />)
    expect(screen.getByTestId('onboarding-identity-issued')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-identity-did')).toHaveTextContent('did:aa:deadbeef')
  })

  it('generates an identity and calls onIssued after the spinner resolves', () => {
    const onIssued = vi.fn()
    render(<Step3IssueIdentity state={EMPTY_STATE} onIssued={onIssued} />)

    fireEvent.click(screen.getByTestId('onboarding-identity-generate'))
    // Spinning phase shows the disabled generating button.
    expect(screen.getByText('generating…')).toBeInTheDocument()

    act(() => {
      vi.advanceTimersByTime(800)
    })

    expect(onIssued).toHaveBeenCalledTimes(1)
    const identity = onIssued.mock.calls[0][0]
    expect(identity.alg).toBe('Ed25519')
    expect(identity.did).toMatch(/^did:aa:[0-9a-f]{32}$/)
    expect(identity.fingerprint).toMatch(/^([0-9A-F]{2}:){7}[0-9A-F]{2}$/)
    // The done glyph (✓) renders once the phase flips, independent of the
    // parent feeding the issued identity back through props.
    expect(screen.getByText('✓')).toBeInTheDocument()
  })

  it('renders the issued summary when the parent feeds the identity back', () => {
    const onIssued = vi.fn()
    const { rerender } = render(
      <Step3IssueIdentity state={EMPTY_STATE} onIssued={onIssued} />,
    )
    fireEvent.click(screen.getByTestId('onboarding-identity-generate'))
    act(() => {
      vi.advanceTimersByTime(800)
    })
    const identity = onIssued.mock.calls[0][0]
    rerender(
      <Step3IssueIdentity state={{ ...EMPTY_STATE, identity }} onIssued={onIssued} />,
    )
    expect(screen.getByTestId('onboarding-identity-issued')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-identity-did')).toHaveTextContent(identity.did)
  })

  it('ignores a second generate click while spinning', () => {
    const onIssued = vi.fn()
    render(<Step3IssueIdentity state={EMPTY_STATE} onIssued={onIssued} />)
    const btn = screen.getByTestId('onboarding-identity-generate')
    fireEvent.click(btn)
    fireEvent.click(btn)
    act(() => {
      vi.advanceTimersByTime(800)
    })
    expect(onIssued).toHaveBeenCalledTimes(1)
  })
})
