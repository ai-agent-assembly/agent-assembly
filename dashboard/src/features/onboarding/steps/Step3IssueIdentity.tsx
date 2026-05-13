import { useState } from 'react'
import type { AgentIdentity, WizardState } from '../types'
import './Steps.css'

export interface Step3IssueIdentityProps {
  state: WizardState
  onIssued: (identity: AgentIdentity) => void
}

type Phase = 'idle' | 'spinning' | 'done'

const HEX = '0123456789abcdef'

function randHex(byteCount: number): string {
  let out = ''
  for (let i = 0; i < byteCount * 2; i++) {
    out += HEX[Math.floor(Math.random() * 16)]
  }
  return out
}

function formatFingerprint(): string {
  const groups: string[] = []
  for (let i = 0; i < 8; i++) groups.push(randHex(1))
  return groups.join(':').toUpperCase()
}

export function Step3IssueIdentity({ state, onIssued }: Step3IssueIdentityProps) {
  const [phase, setPhase] = useState<Phase>(state.identity ? 'done' : 'idle')
  const id = state.identity

  const handleGenerate = () => {
    if (phase !== 'idle') return
    setPhase('spinning')
    window.setTimeout(() => {
      const identity: AgentIdentity = {
        did: `did:aa:${randHex(16)}`,
        alg: 'Ed25519',
        fingerprint: formatFingerprint(),
        issuedAt: new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z',
      }
      onIssued(identity)
      setPhase('done')
    }, 800)
  }

  return (
    <section data-testid="onboarding-step-identity">
      <h2 className="onb-body-title">Issue first agent identity.</h2>
      <p className="onb-body-sub">
        Every agent gets a unique cryptographic identity (DID). The keypair is
        generated locally — the private key never leaves your control plane.
      </p>

      <div className="onb-id-card">
        <div
          className={`onb-id-glyph${phase === 'done' ? ' is-done' : ''}`}
          aria-hidden
        >
          {phase === 'done' ? '✓' : '◯'}
        </div>

        {phase === 'idle' && (
          <>
            <button
              type="button"
              className="onb-id-action-btn"
              data-testid="onboarding-identity-generate"
              onClick={handleGenerate}
            >
              ▸ generate keypair
            </button>
            <div className="onb-id-hint">Ed25519 · 256-bit · ~1.4s</div>
          </>
        )}

        {phase === 'spinning' && (
          <>
            <button type="button" className="onb-id-action-btn" disabled>
              generating…
            </button>
            <div className="onb-id-hint">
              deriving curve point · signing CSR · publishing to registry
            </div>
          </>
        )}

        {phase === 'done' && id && (
          <>
            <div className="onb-id-issued" data-testid="onboarding-identity-issued">
              ✓ identity issued
            </div>
            <dl className="onb-id-out">
              <div className="onb-id-row">
                <dt className="onb-id-key">DID</dt>
                <dd
                  className="onb-id-val"
                  data-testid="onboarding-identity-did"
                >
                  {id.did}
                </dd>
              </div>
              <div className="onb-id-row">
                <dt className="onb-id-key">algorithm</dt>
                <dd className="onb-id-val">{id.alg}</dd>
              </div>
              <div className="onb-id-row">
                <dt className="onb-id-key">fingerprint</dt>
                <dd className="onb-id-val is-fp">{id.fingerprint}</dd>
              </div>
              <div className="onb-id-row">
                <dt className="onb-id-key">issued</dt>
                <dd className="onb-id-val">{id.issuedAt}</dd>
              </div>
            </dl>
          </>
        )}
      </div>
    </section>
  )
}
