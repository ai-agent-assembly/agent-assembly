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
import { useEffect, useRef, useState } from 'react'
import { StatusState, TruthfulValue } from '../../../components/truthfulness'
import {
  absent,
  certain,
  certainFromShapedQuery,
  isKnown,
  mapCertain,
  type Certain,
} from '../../../lib/truthfulness'
import { useRegisteredAgentsQuery, type RegisteredAgents } from '../api'
import { decodeRegistryAnswer } from '../schema'
import type { WizardState } from '../types'
import './Steps.css'

export interface Step5EnrollAgentProps {
  state: WizardState
  onEnrolled: () => void
}

/** Reason shown before the operator has asked the registry anything. */
const NOT_ASKED = 'Start the listener to poll the gateway for registered agents'

export function Step5EnrollAgent({ state, onEnrolled }: Readonly<Step5EnrollAgentProps>) {
  // A resumed session that once saw an agent is not evidence that one is
  // registered now, so resuming re-enters the poll and re-asks rather than
  // restoring a "registered" badge from localStorage.
  const [polling, setPolling] = useState(state.enrolled)

  const query = useRegisteredAgentsQuery(polling)
  // AAASM-5380: folded through `decodeRegistryAnswer` so a `200` whose body has
  // no `total` or a non-array `items` reports an absence naming the field,
  // rather than a cast that rendered an empty meter and "no agents registered
  // yet" or threw in `.map`. Off the poll it stays `not-evaluated`.
  const registry: Certain<RegisteredAgents> = polling
    ? certainFromShapedQuery(query, decodeRegistryAnswer)
    : absent('not-evaluated', NOT_ASKED)
  const enrolledCount = mapCertain(registry, (r) => r.total)
  const agents = isKnown(registry) ? registry.value.items : []

  // "Registered" is derived from the poll, never stored: there is no state to
  // get out of step with the registry, and no way to reach the badge except by
  // the gateway having answered with at least one agent. A known zero is a real
  // answer — asked and answered "none" — so it drives the meter honestly; any
  // absence leaves it empty.
  const hasAgents = isKnown(enrolledCount) && enrolledCount.value > 0

  // The parent is told once. `onEnrolled` is a fresh closure on every render of
  // the wizard, so without the latch this would re-fire on each poll tick.
  const reported = useRef(false)
  useEffect(() => {
    if (!hasAgents || reported.current) return
    reported.current = true
    onEnrolled()
  }, [hasAgents, onEnrolled])

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
        {!polling && (
          <button
            type="button"
            className="onb-btn"
            data-testid="onboarding-enroll-start"
            onClick={() => setPolling(true)}
          >
            ▸ start listener
          </button>
        )}
        {polling && !hasAgents && (
          <span className="onb-id-action-btn live" data-testid="onboarding-enroll-listening">
            polling…
          </span>
        )}
        {polling && hasAgents && (
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
        {/* Gated on the same `hasAgents` as the badge and the meter, not on
            `agents.length`. Reading the page length here while the badge read
            the registry `total` would let the two disagree — "agent registered"
            above "no agents registered yet" — for any answer where the two
            differ. */}
        {isKnown(registry) && !hasAgents && (
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
