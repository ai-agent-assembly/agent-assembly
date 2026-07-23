import { VERDICT_META, type Verdict } from '../../features/trace/decision'
import './VerdictChip.css'

export interface VerdictChipProps {
  readonly verdict: Verdict
  /** `full` shows the `✓ ALLOWED` label; `compact` shows the glyph only (timeline rows). */
  readonly variant?: 'full' | 'compact'
}

/**
 * Decision verdict pill — ALLOWED / NARROWED / SCRUBBED / PENDING / DENIED
 * (hi-fi `trace.jsx` `DEC_LABEL` / `DEC_CHIP`). Colour keys off the design
 * tokens in `VERDICT_META`, so it tracks the light/dark theme automatically.
 */
export function VerdictChip({ verdict, variant = 'full' }: VerdictChipProps) {
  const meta = VERDICT_META[verdict]
  const text = variant === 'compact' ? meta.icon : meta.label
  return (
    <span
      className="verdict-chip"
      data-testid="verdict-chip"
      data-verdict={verdict}
      style={{ color: meta.colorVar, background: meta.bgVar, borderColor: meta.colorVar }}
      title={meta.label}
    >
      {text}
    </span>
  )
}
