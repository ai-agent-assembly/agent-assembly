/**
 * Step 5 — enrollment (AAASM-5133).
 *
 * The step used to derive `enrolledCount` from its own phase variable
 * (`phase === 'live' ? 1 : 0`) 800 ms after a button press, and to replay three
 * hardcoded "incoming calls" with frozen 14:02 timestamps. Nothing was polled,
 * so it reported a successful enrollment — and governed traffic — against a
 * gateway with zero registered agents.
 *
 * It now polls the registry. The count is whatever `GET /api/v1/agents` says,
 * the listed agents are the ones it returned, and a failed poll renders as an
 * absence rather than as a zero.
 */
import { useEffect, useState } from 'react'
import { StatusState, TruthfulValue } from '../../../components/truthfulness'
import {
  absent,
  certain,
  certainFromQuery,
  isKnown,
  mapCertain,
  type Certain,
} from '../../../lib/truthfulness'
import { useRegisteredAgentsQuery, type RegisteredAgents } from '../api'
import type { WizardState } from '../types'
import './Steps.css'

export interface Step5EnrollAgentProps {
  state: WizardState
  onEnrolled: () => void
}

/**
 * `live` is now a *finding*, not a timer expiry: it is only reachable from a
 * poll that returned at least one registered agent.
 */
type Phase = 'idle' | 'listening' | 'live'

/** Reason shown before the operator has asked the registry anything. */
const NOT_ASKED = 'Start the listener to poll the gateway for registered agents'

export function Step5EnrollAgent({ state, onEnrolled }: Readonly<Step5EnrollAgentProps>) {
  // A resumed session that once saw an agent is not evidence that one is
  // registered now, so resuming re-enters `listening` and re-asks rather than
  // restoring a `live` badge from localStorage.
  const [phase, setPhase] = useState<Phase>(state.enrolled ? 'listening' : 'idle')

  const query = useRegisteredAgentsQuery(phase !== 'idle')
  const registry: Certain<RegisteredAgents> =
    phase === 'idle' ? absent('not-evaluated', NOT_ASKED) : certainFromQuery(query)
  const enrolledCount = mapCertain(registry, (r) => r.total)
  const agents = isKnown(registry) ? registry.value.items : []

  useEffect(() => {
    if (phase !== 'listening') return
    if (!isKnown(registry) || registry.value.total <= 0) return
    setPhase('live')
    onEnrolled()
  }, [phase, registry, onEnrolled])

  // A known zero is a real answer — the gateway was asked and holds no agents —
  // so it drives the bar honestly. Any absence leaves the bar empty.
  const hasAgents = isKnown(enrolledCount) && enrolledCount.value > 0

  return (
    <section data-testid="onboarding-step-enroll">
      <h2 className="onb-body-title">Enroll your first agent.</h2>
      <p className="onb-body-sub">
        Run your agent now (or any test script that imports the SDK). This step
        polls the gateway&rsquo;s agent registry and reports what it finds.
      </p>

      <div className="onb-enroll-meter">
        <div className="onb-enroll-row">
          <span className="onb-enroll-label">registered agents</span>
          <span
            className={`onb-enroll-count${hasAgents ? ' is-live' : ''}`}
            data-testid="onboarding-enroll-count"
          >
            <TruthfulValue value={enrolledCount} testId="onboarding-enroll-count-value" />{' '}
            <span className="onb-enroll-count-total">/ ∞</span>
          </span>
        </div>
        <div className="onb-enroll-bar" aria-hidden>
          <div className="onb-enroll-bar-fill" style={{ width: hasAgents ? '8%' : '0%' }} />
        </div>
      </div>

      <div className="onb-term-meta">
        <span className="onb-term-meta-label">gateway agent registry</span>
        {phase === 'idle' && (
          <button
            type="button"
            className="onb-btn"
            data-testid="onboarding-enroll-start"
            onClick={() => setPhase('listening')}
          >
            ▸ start listener
          </button>
        )}
        {phase === 'listening' && (
          <span className="onb-id-action-btn live" data-testid="onboarding-enroll-listening">
            polling…
          </span>
        )}
        {phase === 'live' && (
          <span className="onb-id-action-btn live" data-testid="onboarding-enroll-connected">
            agent registered
          </span>
        )}
      </div>

      <div className="onb-enroll-pings" data-testid="onboarding-enroll-pings">
        {!isKnown(registry) && (
          <StatusState
            state={registry.state}
            title={
              registry.state === 'unavailable'
                ? 'The agent registry could not be read'
                : 'No registry answer yet'
            }
            detail={registry.detail}
            testId="onboarding-enroll-absent"
          />
        )}
        {isKnown(registry) && agents.length === 0 && (
          <div className="onb-enroll-pings-empty" data-testid="onboarding-enroll-empty">
            {'// the registry answered: no agents registered yet'}
          </div>
        )}
        {agents.map((agent) => (
          <div
            key={agent.id}
            className="onb-enroll-ping"
            data-testid={`onboarding-enroll-agent-${agent.id}`}
          >
            <span className="onb-ping-action">{agent.name}</span>{' '}
            <span className="onb-ping-tag">· {agent.framework}</span>{' '}
            <span className="onb-ping-time">
              <TruthfulValue
                value={certain(agent.last_event, 'unknown', 'The registry reported no last event')}
                testId={`onboarding-enroll-agent-last-event-${agent.id}`}
              />
            </span>
          </div>
        ))}
      </div>
    </section>
  )
}
