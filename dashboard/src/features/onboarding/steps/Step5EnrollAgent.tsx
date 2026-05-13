import { useState } from 'react'
import type { WizardState } from '../types'
import './Steps.css'

export interface Step5EnrollAgentProps {
  state: WizardState
  onEnrolled: () => void
}

interface Ping {
  id: number
  time: string
  action: string
  tag: string
}

type Phase = 'idle' | 'listening' | 'live'

const COMPLETED_PINGS: Ping[] = [
  { id: 3, time: '14:02:14', action: 'gmail.read', tag: 'allowed-by-baseline' },
  { id: 2, time: '14:02:13', action: 'capability.list', tag: 'cached' },
  { id: 1, time: '14:02:11', action: 'phone-home (heartbeat)', tag: 'identity-verified' },
]

export function Step5EnrollAgent({ state, onEnrolled }: Step5EnrollAgentProps) {
  const [phase, setPhase] = useState<Phase>(state.enrolled ? 'live' : 'idle')
  const [pings, setPings] = useState<Ping[]>(state.enrolled ? COMPLETED_PINGS : [])

  const handleStart = () => {
    if (phase !== 'idle') return
    setPhase('listening')
    window.setTimeout(() => {
      setPhase('live')
      setPings(COMPLETED_PINGS)
      onEnrolled()
    }, 800)
  }

  const enrolledCount = phase === 'live' ? 1 : 0

  return (
    <section data-testid="onboarding-step-enroll">
      <h2 className="onb-body-title">Enroll your first agent.</h2>
      <p className="onb-body-sub">
        Run your agent now (or any test script that imports the SDK). The control
        plane will detect the first authenticated call and complete enrollment.
      </p>

      <div className="onb-enroll-meter">
        <div className="onb-enroll-row">
          <span className="onb-enroll-label">enrolled agents</span>
          <span
            className={`onb-enroll-count${enrolledCount > 0 ? ' is-live' : ''}`}
            data-testid="onboarding-enroll-count"
          >
            {enrolledCount}{' '}
            <span style={{ fontSize: 14, color: 'var(--ink-4)' }}>/ ∞</span>
          </span>
        </div>
        <div className="onb-enroll-bar" aria-hidden>
          <div
            className="onb-enroll-bar-fill"
            style={{ width: enrolledCount > 0 ? '8%' : '0%' }}
          />
        </div>
      </div>

      <div className="onb-term-meta">
        <span className="onb-term-meta-label">incoming agent calls</span>
        {phase === 'idle' && (
          <button
            type="button"
            className="onb-pkg-tab is-active"
            data-testid="onboarding-enroll-start"
            onClick={handleStart}
          >
            ▸ start listener
          </button>
        )}
        {phase === 'listening' && (
          <span className="onb-term-meta-label" data-testid="onboarding-enroll-listening">
            listening…
          </span>
        )}
        {phase === 'live' && (
          <span className="onb-term-meta-label" data-testid="onboarding-enroll-connected">
            connected
          </span>
        )}
      </div>

      <div className="onb-enroll-pings" data-testid="onboarding-enroll-pings">
        {pings.length === 0 && phase === 'idle' && (
          <div className="onb-enroll-pings-empty">
            // no calls yet — run your agent to phone home
          </div>
        )}
        {pings.length === 0 && phase === 'listening' && (
          <div className="onb-enroll-pings-empty">
            // awaiting first authenticated call…
          </div>
        )}
        {pings.map((p) => (
          <div
            key={p.id}
            className="onb-enroll-ping"
            data-testid={`onboarding-enroll-ping-${p.id}`}
          >
            <span className="onb-ping-time">{p.time}</span>{' '}
            <span className="onb-ping-action">{p.action}</span>{' '}
            <span className="onb-ping-tag">· {p.tag}</span>
          </div>
        ))}
      </div>
    </section>
  )
}
