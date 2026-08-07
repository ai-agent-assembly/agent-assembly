/**
 * What one drill-down row is evidence of (AAASM-5360).
 *
 * The per-event counterpart of `measures.readPrevention`. The aggregate panel
 * refuses to show a rate without its unmeasured share; a single row has the same
 * problem in miniature, and worse — `prevented_transmission` is a **boolean**,
 * and a boolean has no room for "nobody looked".
 *
 * `false` on that field means one of two completely different things:
 *
 *  - evidence was recorded and the four ADR 0032 §8 conditions did not hold, or
 *  - `transmission_evidence` is `not_recorded`, so no evidence existed and the
 *    conditions could not have held whatever actually happened to the payload.
 *
 * On every build shipping today it is always the second (AAASM-5685). A column
 * of red ✗ marks would report a product that is failing to prevent things, from
 * a product that is not measuring whether it does. So {@link readEventPrevention}
 * reads the evidence column first and the boolean second.
 *
 * The same shape applies to `inspection_failure_path`: "completed" is the only
 * value that means the detection pass ran to the end, and every other value is a
 * reason the row's own finding count may be an undercount. That is never folded
 * into a clean-looking row (ADR 0032 forbidden design #2).
 */
import type { SensitiveDataEventSummary } from './schema'

/** What a row's prevention flag is evidence of. */
export type EventPreventionKind =
  /** Evidence recorded, and all four §8 conditions held. */
  | 'prevented'
  /** Evidence recorded, and they did not. A measured negative. */
  | 'not-prevented'
  /** No transmission evidence at all. The flag says nothing. */
  | 'unmeasured'

export interface EventPreventionReading {
  readonly kind: EventPreventionKind
  /** The short cell label. */
  readonly label: string
  /** The sentence shown on the detail view and as the cell's tooltip. */
  readonly explanation: string
}

/**
 * The evidence value the producer writes when nothing observed the bytes.
 *
 * Matched exactly rather than by "anything that is not a forwarding verdict":
 * a value this dashboard does not recognise is not the same as a value that
 * means "unrecorded", and guessing would put the unmeasured label on a row that
 * carries evidence of some kind.
 */
const NOT_RECORDED = 'not_recorded'

export function readEventPrevention(event: SensitiveDataEventSummary): EventPreventionReading {
  if (event.transmission_evidence === NOT_RECORDED) {
    return {
      kind: 'unmeasured',
      label: 'Not measured',
      explanation:
        'Nothing recorded what happened to this action’s bytes, so whether transmission was prevented could not be established either way. This is not a finding that it was not prevented.',
    }
  }
  if (event.prevented_transmission) {
    return {
      kind: 'prevented',
      label: 'Prevented',
      explanation: `All four ADR 0032 §8 prevention conditions hold for this action: it was decided at ${event.enforcement_point}, enforcement was ${event.enforcement_mode}, and the recorded transmission evidence is ${event.transmission_evidence}.`,
    }
  }
  return {
    kind: 'not-prevented',
    label: 'Not prevented',
    explanation: `Transmission evidence was recorded for this action (${event.transmission_evidence}) and the four ADR 0032 §8 prevention conditions did not all hold, so this is a measured negative rather than an absent measurement.`,
  }
}

/** Whether a row's detection pass ran to completion, and what it means if not. */
export interface EventInspectionReading {
  readonly complete: boolean
  readonly label: string
  readonly explanation: string
}

export function readEventInspection(event: SensitiveDataEventSummary): EventInspectionReading {
  if (event.inspection_failure_path === 'completed') {
    return {
      complete: true,
      label: 'Completed',
      explanation: 'The detection pass ran to completion for this action.',
    }
  }
  return {
    complete: false,
    label: event.inspection_failure_path,
    explanation: `This action’s detection pass did not run to completion (${event.inspection_failure_path}). Its finding count is what the pass managed to establish, not what the action carried, and nothing here should be read as a clean result.`,
  }
}

/**
 * How many of a row's findings were rewritten, phrased so it cannot be read as
 * a delivery claim.
 *
 * On a blocked action nothing reached the wire, however many findings were
 * transformed first — so the sentence says "rewritten before the decision was
 * applied", never "redacted and sent".
 */
export function transformationSentence(event: SensitiveDataEventSummary): string {
  const findings = event.finding_count === 1 ? 'finding' : 'findings'
  const rewritten = event.transformed_finding_count === 1 ? 'was' : 'were'
  if (event.verdict === 'deny') {
    return `${event.transformed_finding_count} of this action’s ${event.finding_count} ${findings} ${rewritten} rewritten before the action was refused. The action was refused, so nothing reached the destination.`
  }
  return `${event.transformed_finding_count} of this action’s ${event.finding_count} ${findings} ${rewritten} rewritten before the decision was applied.`
}
