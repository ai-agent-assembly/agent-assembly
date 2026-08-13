import { VERDICT_META, type Verdict } from '../../features/trace/decision'
import './VerdictChip.css'

export interface VerdictChipProps {
  readonly verdict: Verdict
  /** `full` shows the `✓ ALLOWED` label; `compact` shows the glyph only (timeline rows). */
  readonly variant?: 'full' | 'compact'
  /**
   * Corner shape. `pill` (default) keeps the existing 9999px rounding so every
   * current caller is untouched; `square` renders the ratified 2px-radius chip
   * from the hi-fi `.chip` mock (design-parity Story AAASM-5075). New Wave-2
   * surfaces (Agent-detail / Live-ops / Trace) opt into `square`.
   */
  readonly shape?: 'square' | 'pill'
}

/**
 * Decision verdict chip — ALLOWED / NARROWED / SCRUBBED / PENDING / DENIED
 * (hi-fi `trace.jsx` `DEC_LABEL` / `DEC_CHIP`). Colour keys off the design
 * tokens in `VERDICT_META`, so it tracks the light/dark theme automatically.
 *
 * `shape` selects rounding only (pill vs the ratified square corners); it never
 * changes the palette, label, or sizing, so it is a purely additive, opt-in
 * seam for the Wave-2 pages that consume the same primitive.
 */
export function VerdictChip({ verdict, variant = 'full', shape = 'pill' }: VerdictChipProps) {
  const meta = VERDICT_META[verdict]
  const text = variant === 'compact' ? meta.icon : meta.label
  return (
    <span
      className={shape === 'square' ? 'verdict-chip verdict-chip--square' : 'verdict-chip'}
      data-testid="verdict-chip"
      data-verdict={verdict}
      data-shape={shape}
      style={{ color: meta.colorVar, background: meta.bgVar, borderColor: meta.colorVar }}
      title={meta.label}
    >
      {text}
    </span>
  )
}
