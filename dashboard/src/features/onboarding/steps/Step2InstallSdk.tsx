import { useState } from 'react'
import type { WizardState } from '../types'
import './Steps.css'

export interface Step2InstallSdkProps {
  state: WizardState
  onVerified: () => void
}

type PackageManager = 'pip' | 'npm' | 'go'
type Phase = 'idle' | 'running' | 'verified'

/** The copy button's outcome. `failed` did not exist before AAASM-5145. */
type CopyState = 'idle' | 'copied' | 'failed'

const COPY_RESET_MS = 1400

const COMMANDS: Record<PackageManager, string> = {
  pip: 'pip install agent-assembly',
  npm: 'npm install @agent-assembly/sdk',
  go: 'go get github.com/agent-assembly/sdk-go',
}

interface Line {
  kind: 'prompt' | 'cmd' | 'out' | 'ok'
  text: string
}

const VERIFIED_LINES: Line[] = [
  { kind: 'prompt', text: '$ ' },
  { kind: 'cmd', text: 'aa-cli verify' },
  { kind: 'out', text: 'connecting to runtime…  done.' },
  { kind: 'out', text: 'sdk version    1.4.2 (latest)' },
  { kind: 'out', text: 'control-plane  https://api.agent-assembly.com' },
  { kind: 'ok', text: '✓ verified · ready to enroll' },
]

export function Step2InstallSdk({ state, onVerified }: Readonly<Step2InstallSdkProps>) {
  const [pkg, setPkg] = useState<PackageManager>('pip')
  const [copyState, setCopyState] = useState<CopyState>('idle')
  const [phase, setPhase] = useState<Phase>(state.installVerified ? 'verified' : 'idle')
  const [lines, setLines] = useState<Line[]>(state.installVerified ? VERIFIED_LINES : [])

  const handleCopy = async () => {
    // `navigator.clipboard` is undefined in a non-secure context — precisely the
    // self-hosted http://<gateway-host>:<port> case — so the member access below
    // throws synchronously inside this async function. Reporting "✓ copied"
    // regardless was AAASM-5145; the success flag now lives inside the `try`,
    // matching `features/iam/RevealOnceModal.tsx`.
    try {
      await navigator.clipboard.writeText(COMMANDS[pkg])
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
    globalThis.setTimeout(() => setCopyState('idle'), COPY_RESET_MS)
  }

  const handleRun = () => {
    if (phase === 'running') return
    setPhase('running')
    setLines([
      { kind: 'prompt', text: '$ ' },
      { kind: 'cmd', text: 'aa-cli verify' },
      { kind: 'out', text: 'connecting to runtime…' },
    ])
    globalThis.setTimeout(() => {
      setLines(VERIFIED_LINES)
      setPhase('verified')
      onVerified()
    }, 600)
  }

  let verifyButtonLabel: string
  if (phase === 'idle') verifyButtonLabel = '▸ run aa-cli verify'
  else if (phase === 'running') verifyButtonLabel = 'verifying…'
  else verifyButtonLabel = '↻ re-run'

  let copyLabel: string
  if (copyState === 'copied') copyLabel = '✓ copied'
  else if (copyState === 'failed') copyLabel = '✗ copy failed'
  else copyLabel = 'copy'

  return (
    <section data-testid="onboarding-step-install">
      <h2 className="onb-body-title">Install the SDK.</h2>
      <p className="onb-body-sub">
        Drop this in your agent project. It auto-loads on first import — no
        boilerplate.
      </p>

      <div className="onb-pkg-row">
        <div className="onb-pkg-tabs" role="tablist" aria-label="package manager">
          {(['pip', 'npm', 'go'] as const).map((p) => (
            <button
              key={p}
              type="button"
              role="tab"
              aria-selected={pkg === p}
              className={`onb-pkg-tab${pkg === p ? ' is-active' : ''}`}
              data-testid={`onboarding-install-tab-${p}`}
              onClick={() => setPkg(p)}
            >
              {p}
            </button>
          ))}
        </div>
        <code className="onb-pkg-cmd" data-testid="onboarding-install-cmd">
          $ {COMMANDS[pkg]}
        </code>
        <button
          type="button"
          className={`onb-pkg-copy is-${copyState}`}
          data-testid="onboarding-install-copy"
          data-copy-state={copyState}
          onClick={handleCopy}
        >
          {copyLabel}
        </button>
      </div>
      {copyState === 'failed' && (
        <p className="onb-copy-error" role="alert" data-testid="onboarding-install-copy-error">
          The clipboard is unavailable here — copy the command above by hand.
        </p>
      )}

      <div className="onb-term-meta">
        <span className="onb-term-meta-label">verify connection</span>
        <button
          type="button"
          className="onb-btn"
          data-testid="onboarding-install-verify"
          onClick={handleRun}
          disabled={phase === 'running'}
        >
          {verifyButtonLabel}
        </button>
      </div>

      <div className="onb-term" data-testid="onboarding-install-terminal">
        {lines.length === 0 ? (
          <div className="onb-term-line onb-term-faint">
            # run verify above to check the SDK reaches the control-plane
          </div>
        ) : (
          lines.map((l) => (
            <div key={`${l.kind}-${l.text}`} className="onb-term-line">
              {l.kind === 'prompt' && <span className="onb-term-prompt">{l.text}</span>}
              {l.kind === 'cmd' && <span className="onb-term-cmd">{l.text}</span>}
              {l.kind === 'out' && <span className="onb-term-out">{l.text}</span>}
              {l.kind === 'ok' && (
                <span className="onb-term-ok" data-testid="onboarding-install-ok">
                  {l.text}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </section>
  )
}
