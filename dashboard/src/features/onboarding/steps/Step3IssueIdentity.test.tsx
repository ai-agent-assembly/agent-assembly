import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Step3IssueIdentity } from './Step3IssueIdentity'

/**
 * Every claim the step used to make about key material (AAASM-5179). None of it
 * was true: no `crypto.subtle` call exists anywhere in the dashboard, the value
 * shown was 24 random bytes, and a browser cannot write to a filesystem path.
 */
const REMOVED_CLAIMS = [
  '~/.aa/keys/',
  'do not commit',
  'generate keypair',
  'deriving curve point',
  'signing CSR',
  'publishing to registry',
  'private key',
  'identity issued',
  'Ed25519',
  'fingerprint',
  'did:aa:',
]

describe('Step3IssueIdentity', () => {
  it('renders the step as not-supported rather than issuing anything', () => {
    render(<Step3IssueIdentity />)

    const state = screen.getByTestId('onboarding-identity-unsupported')
    expect(state).toHaveAttribute('data-truth-state', 'not-supported')
    expect(state).toHaveTextContent('Not supported')
    expect(state).toHaveTextContent(/not available from the dashboard/i)
  })

  it('offers no action, because there is no successful production path', () => {
    render(<Step3IssueIdentity />)

    expect(screen.queryByTestId('onboarding-identity-generate')).toBeNull()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('makes none of the removed key-material claims', () => {
    const { container } = render(<Step3IssueIdentity />)
    const text = container.textContent ?? ''

    for (const claim of REMOVED_CLAIMS) {
      expect(text.toLowerCase()).not.toContain(claim.toLowerCase())
    }
  })

  it('states plainly that no key material is produced by the browser', () => {
    render(<Step3IssueIdentity />)

    expect(screen.getByTestId('onboarding-identity-unsupported')).toHaveTextContent(
      /no key material is created, transmitted, or written to disk/i,
    )
  })

  it('announces the absence to assistive tech rather than reading as a healthy step', () => {
    render(<Step3IssueIdentity />)

    const state = screen.getByTestId('onboarding-identity-unsupported')
    // `not-supported` is a permanent, benign gap, so it is a polite status —
    // never an alert (see StatusState.roleFor).
    expect(state).toHaveAttribute('role', 'status')
    expect(state).toHaveTextContent('Not supported — the backend cannot provide this value.')
  })
})
