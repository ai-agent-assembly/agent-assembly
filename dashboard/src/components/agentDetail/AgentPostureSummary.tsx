import { TruthfulValue } from '../truthfulness'
import { isKnown, type Certain } from '../../lib/truthfulness'
import { deriveAgentPosture, postureScale } from './agentPosture'
import { useAgentCapabilityMatrixQuery } from './useAgentCapabilityMatrix'
import './AgentPostureSummary.css'

type BarTone = 'ok' | 'warn' | 'deny' | 'info'

interface PostureBarProps {
  readonly label: string
  readonly value: Certain<number>
  readonly scale: number
  readonly tone: BarTone
  readonly testId: string
}

/**
 * One posture row: a label, a proportional track, and the figure.
 *
 * An absent figure renders **no fill at all** rather than a zero-width one. The
 * distinction is the whole point on this panel: a zero-width bar is what a
 * measured zero looks like, so drawing one for an unmeasured row would restate
 * the bug in pixels after the number itself had been fixed.
 */
function PostureBar({ label, value, scale, tone, testId }: Readonly<PostureBarProps>) {
  const known = isKnown(value)
  const pct = known ? Math.min(100, Math.max(0, (value.value / scale) * 100)) : 0
  return (
    <div className="ad-minibar" data-testid={`${testId}-row`}>
      <div className="ad-minibar__label">{label}</div>
      <div className="ad-minibar__track">
        {known && (
          <span
            className={`ad-minibar__fill ad-minibar__fill--${tone}`}
            style={{ width: `${pct}%` }}
          />
        )}
      </div>
      <div className="ad-minibar__value">
        <TruthfulValue value={value} testId={testId} />
      </div>
    </div>
  )
}

export interface AgentPostureSummaryProps {
  readonly agentId: string
  readonly agentName?: string
}

/**
 * Overview posture summary (AAASM-5131).
 *
 * Reads the same agent-scoped capability matrix the Overview's capability panel
 * renders below it — one shared query key, so mounting both costs one request —
 * and reports only what that projection can support. See `agentPosture.ts` for
 * why Narrow and Approval are permanently absent here rather than counted.
 *
 * The caption is not decoration: with two of four rows showing `—`, an operator
 * who cannot see *why* will read the panel as broken rather than as honest.
 *
 * The row labels say "decisions" where `design/v2/hi-fi/agent-detail.jsx` says
 * "resources". The mock counts a *resource* as allowed when either its read or
 * its write cell allows — a collapse across verbs that ignores delete and exec
 * and has no counterpart in the API. Counting cells needs no such rule, so the
 * label names the unit that is actually counted; AAASM-5131 called out the
 * previous labels for drifting between the two silently, not for the wording.
 */
export function AgentPostureSummary({ agentId, agentName }: Readonly<AgentPostureSummaryProps>) {
  const outcome = useAgentCapabilityMatrixQuery(agentId, agentName)
  const posture = deriveAgentPosture(outcome)
  const scale = postureScale(posture)

  return (
    <div className="ad-posture" data-testid="agent-detail-posture">
      <PostureBar
        label="allow decisions"
        value={posture.allow}
        scale={scale}
        tone="ok"
        testId="agent-posture-allow"
      />
      <PostureBar
        label="narrow decisions"
        value={posture.narrow}
        scale={scale}
        tone="warn"
        testId="agent-posture-narrow"
      />
      <PostureBar
        label="deny decisions"
        value={posture.deny}
        scale={scale}
        tone="deny"
        testId="agent-posture-deny"
      />
      <PostureBar
        label="approval decisions"
        value={posture.approval}
        scale={scale}
        tone="info"
        testId="agent-posture-approval"
      />
      <p className="ad-posture__caption" data-testid="agent-posture-caption">
        Counted over this agent&rsquo;s capability-matrix cells (resource × verb). Narrow and
        approval are decided per action by other policy stages, so this projection never measures
        them.
      </p>
    </div>
  )
}
