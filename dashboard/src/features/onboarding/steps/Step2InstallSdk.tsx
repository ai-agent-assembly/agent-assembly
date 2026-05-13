import { useState } from 'react'
import type { WizardState } from '../types'
import './Steps.css'

export interface Step2InstallSdkProps {
  state: WizardState
  onVerified: () => void
}

type PackageManager = 'pip' | 'npm' | 'go'
type Phase = 'idle' | 'running' | 'verified'

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
  { kind: 'out', text: 'control-plane  https://api.agent-assembly.io' },
  { kind: 'ok', text: '✓ verified · ready to enroll' },
]

export function Step2InstallSdk({ state, onVerified }: Step2InstallSdkProps) {
  const [pkg, setPkg] = useState<PackageManager>('pip')
  const [copied, setCopied] = useState(false)
  const [phase, setPhase] = useState<Phase>(state.installVerified ? 'verified' : 'idle')
  const [lines, setLines] = useState<Line[]>(state.installVerified ? VERIFIED_LINES : [])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(COMMANDS[pkg])
    } catch {
      // ignore clipboard failure (older browsers / no permission)
    }
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1400)
  }

  const handleRun = () => {
    if (phase === 'running') return
    setPhase('running')
    setLines([
      { kind: 'prompt', text: '$ ' },
      { kind: 'cmd', text: 'aa-cli verify' },
      { kind: 'out', text: 'connecting to runtime…' },
    ])
    window.setTimeout(() => {
      setLines(VERIFIED_LINES)
      setPhase('verified')
      onVerified()
    }, 600)
  }

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
          className={`onb-pkg-copy${copied ? ' is-copied' : ''}`}
          data-testid="onboarding-install-copy"
          onClick={handleCopy}
        >
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>

      <div className="onb-term-meta">
        <span className="onb-term-meta-label">verify connection</span>
        <button
          type="button"
          className="onb-pkg-tab is-active"
          data-testid="onboarding-install-verify"
          onClick={handleRun}
          disabled={phase === 'running'}
        >
          {phase === 'idle'
            ? '▸ run aa-cli verify'
            : phase === 'running'
              ? 'verifying…'
              : '↻ re-run'}
        </button>
      </div>

      <div className="onb-term" data-testid="onboarding-install-terminal">
        {lines.length === 0 ? (
          <div className="onb-term-line onb-term-faint">
            # run verify above to check the SDK reaches the control-plane
          </div>
        ) : (
          lines.map((l, i) => (
            <div key={i} className="onb-term-line">
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
