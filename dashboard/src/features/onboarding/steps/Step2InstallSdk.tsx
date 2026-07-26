import { useState } from 'react'
import { AbsenceMarker } from '../../../components/truthfulness'
import {
  TRUTH_STATE_META,
  certainFromQuery,
  isKnown,
  type Certain,
} from '../../../lib/truthfulness'
import { probeGatewayHealth, type GatewayHealth } from '../api'
import './Steps.css'

export interface Step2InstallSdkProps {
  /** Fired only after the gateway itself answered `200` with `status: "ok"`. */
  onReachable: () => void
}

type PackageManager = 'pip' | 'npm' | 'go'

/**
 * `verified` is deliberately absent from this union.
 *
 * The step used to carry a `verified` phase reached by a 600 ms timer, which is
 * what let it announce success while the gateway was down (AAASM-5132). The
 * phase now records only whether a probe is in flight; *what the probe found*
 * lives in a `Certain<GatewayHealth>`, which cannot be read without narrowing.
 */
type Phase = 'idle' | 'probing' | 'answered'

/** The copy button's outcome. `failed` did not exist before AAASM-5145. */
type CopyState = 'idle' | 'copied' | 'failed'

const COMMANDS: Record<PackageManager, string> = {
  pip: 'pip install agent-assembly',
  npm: 'npm install @agent-assembly/sdk',
  go: 'go get github.com/agent-assembly/sdk-go',
}

const COPY_RESET_MS = 1400

export interface Line {
  kind: 'prompt' | 'cmd' | 'out' | 'ok' | 'warn' | 'err'
  text: string
}

/** The request, echoed so the operator can see exactly what was asked. */
const REQUEST_LINES: readonly Line[] = [
  { kind: 'prompt', text: '$ ' },
  { kind: 'cmd', text: 'GET /api/v1/health' },
]

function formatChecks(checks: GatewayHealth['checks']): string {
  const entries = Object.entries(checks)
  if (entries.length === 0) return 'none reported'
  return entries.map(([name, status]) => `${name}=${status}`).join('  ')
}

/**
 * Turn a probe outcome into terminal lines.
 *
 * Exported and pure so every branch — including the two that were previously
 * untypeable, `warn` and `err` — is reachable from a unit test without driving
 * the component. The one thing this function may never do is emit an `ok` line
 * for anything other than a gateway that answered with `status: "ok"`.
 */
export function buildProbeLines(result: Certain<GatewayHealth>): Line[] {
  if (!isKnown(result)) {
    const meta = TRUTH_STATE_META[result.state]
    return [
      ...REQUEST_LINES,
      { kind: 'err', text: `✗ ${meta.label.toLowerCase()} — the gateway did not answer` },
      { kind: 'err', text: result.detail ?? 'no response' },
    ]
  }

  const health = result.value
  const body: Line[] = [
    ...REQUEST_LINES,
    { kind: 'out', text: `gateway version  ${health.version}` },
    { kind: 'out', text: `api version      ${health.api_version}` },
    { kind: 'out', text: `subsystems       ${formatChecks(health.checks)}` },
  ]

  if (health.status !== 'ok') {
    return [...body, { kind: 'warn', text: `! gateway reachable but reports "${health.status}"` }]
  }
  return [...body, { kind: 'ok', text: '✓ gateway reachable' }]
}

export function Step2InstallSdk({ onReachable }: Readonly<Step2InstallSdkProps>) {
  const [pkg, setPkg] = useState<PackageManager>('pip')
  const [copyState, setCopyState] = useState<CopyState>('idle')
  const [phase, setPhase] = useState<Phase>('idle')
  // Null until the operator asks. A resumed session is not evidence that the
  // gateway is up *now*, so the persisted flag never seeds a transcript here —
  // the step re-asks rather than replaying an old verdict.
  const [result, setResult] = useState<Certain<GatewayHealth> | null>(null)

  const handleCopy = async () => {
    // `navigator.clipboard` is undefined in a non-secure context — precisely the
    // self-hosted http://<gateway-host>:<port> case — so the member access below
    // throws synchronously inside this async function. Reporting "✓ copied"
    // regardless was AAASM-5145; the success flag now lives inside the `try`.
    try {
      await navigator.clipboard.writeText(COMMANDS[pkg])
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
    globalThis.setTimeout(() => setCopyState('idle'), COPY_RESET_MS)
  }

  // Re-entry is prevented by the button's own `disabled` while `phase` is
  // 'probing', so there is no second guard here to go stale against it.
  const handleProbe = async () => {
    setPhase('probing')
    setResult(null)
    const certain = certainFromQuery(await probeGatewayHealth())
    setResult(certain)
    setPhase('answered')
    if (isKnown(certain) && certain.value.status === 'ok') {
      onReachable()
    }
  }

  let probeButtonLabel: string
  if (phase === 'probing') probeButtonLabel = 'checking…'
  else if (phase === 'idle') probeButtonLabel = '▸ check gateway connection'
  else probeButtonLabel = '↻ re-check'

  let copyLabel: string
  if (copyState === 'copied') copyLabel = '✓ copied'
  else if (copyState === 'failed') copyLabel = '✗ copy failed'
  else copyLabel = 'copy'

  let idleHint: string
  if (phase === 'probing') idleHint = '# asking the gateway…'
  else idleHint = '# checks that this browser can reach the gateway — it cannot observe your SDK'

  const lines = result ? buildProbeLines(result) : []

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
        <span className="onb-term-meta-label">gateway connection</span>
        <div className="onb-term-meta-right">
          {result && !isKnown(result) && (
            <AbsenceMarker
              state={result.state}
              detail={result.detail}
              showLabel
              testId="onboarding-install-absent"
            />
          )}
          <button
            type="button"
            className="onb-btn"
            data-testid="onboarding-install-verify"
            onClick={handleProbe}
            disabled={phase === 'probing'}
          >
            {probeButtonLabel}
          </button>
        </div>
      </div>

      <div className="onb-term" data-testid="onboarding-install-terminal">
        {lines.length === 0 ? (
          <div className="onb-term-line onb-term-faint">{idleHint}</div>
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
              {l.kind === 'warn' && (
                <span className="onb-term-warn" data-testid="onboarding-install-warn">
                  {l.text}
                </span>
              )}
              {l.kind === 'err' && (
                <span className="onb-term-err" data-testid="onboarding-install-err">
                  {l.text}
                </span>
              )}
            </div>
          ))
        )}
      </div>
      <p className="onb-term-caveat" data-testid="onboarding-install-caveat">
        A reachable gateway is not a verified SDK — this page cannot see your agent
        process. Step 5 reports what the registry actually holds once your SDK
        registers.
      </p>
    </section>
  )
}
