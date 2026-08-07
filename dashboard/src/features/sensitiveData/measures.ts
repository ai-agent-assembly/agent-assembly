/**
 * What a sensitive-data figure means, and what it may be called (AAASM-5360).
 *
 * Three separate conflations are possible on this surface, and every one of them
 * would read as a reassuring number. This module is the single place each is
 * resolved, so a component cannot re-decide any of them locally.
 *
 * ## 1. An event count and a finding count are different numbers
 *
 * ADR 0032 §8's worked example: one action carrying three findings, two of them
 * rewritten before the action was refused, produces `event_count = 1`,
 * `finding_count = 3`, `blocked_event_count = 1`, `blocked_finding_count = 3`,
 * `redacted_event_count = 0`, `redacted_finding_count = 2`. Six true numbers
 * about one action. A card reading `3` with no unit, or `1` with no unit, is a
 * defect whichever of the two it happens to be.
 *
 * So there is no way to describe a figure here without its unit:
 * {@link CountMeasure} carries a {@link CountUnit}, {@link measureUnitNoun}
 * turns it into the word rendered beside the number, and
 * {@link countMeasures} is the only constructor. A component that wants a
 * number has to take the noun with it.
 *
 * `redacted_finding_count` is labelled *redaction operations performed*, not
 * "findings redacted and sent": it counts transformations the pipeline carried
 * out, including on actions it then refused, where nothing reached the wire at
 * all. The API's own module doc makes that point; restating it in the label is
 * how it reaches the operator.
 *
 * ## 2. `prevention_rate` is structurally zero on this build (AAASM-5685)
 *
 * Nothing in the product writes `TransmissionEvidence::NotForwarded` today — the
 * gateway producer writes `NotRecorded` unconditionally, because it decides, it
 * does not observe the bytes. So ADR 0032 §8's four prevention conditions can
 * never all hold, `prevented_event_count` is always `0`, and `prevention_rate`
 * is always `0.0` over a non-empty window.
 *
 * Rendering that as **"Prevention rate: 0%"** would be a false governance
 * signal. It reads as *"we prevented nothing"*, when the truth is *"nothing was
 * in a position to measure whether we prevented anything"*. Those are opposite
 * conclusions about the product.
 *
 * AAASM-5359 ships `unmeasured_transmission_event_count` and
 * `unmeasured_transmission_rate` precisely so the difference is legible on the
 * wire. {@link readPrevention} turns the pair into a four-way reading, and
 * {@link preventionHeadline} / {@link preventionQualifier} /
 * {@link preventionStatusLabel} produce text that differs in all three for a
 * structural zero and a measured zero. `PreventionPanel` renders all three; a
 * variant that renders only the rate does not exist and must not be added.
 *
 * ## 3. A lossy window must not render as a complete one
 *
 * AAASM-5660 drew this property for the proxy's evidence sink. Two signals reach
 * *these* endpoints and are surfaced by {@link readInspectionCoverage} and
 * {@link readPageCoverage}:
 *
 *  - `inspection_incomplete_event_count` — actions whose detection pass failed
 *    open, failed closed, or answered from a reduced path. The counters describe
 *    those actions as if inspection had completed, and it did not.
 *  - `total` versus the length of `events` — the drill-down list is a page, the
 *    total is not, and the API's own doc says a UI pairing them must label which
 *    is which.
 *
 * A third signal does **not** exist and is not invented here: no field on any of
 * these responses reports that the underlying window was rotated, truncated or
 * partially lost. The projection has no retention tier, so nothing is expected
 * to be dropped silently; but "nothing is expected to be dropped" is not the
 * same claim as "this window is known complete", and this module makes only the
 * first. See `readInspectionCoverage`'s doc for the exact wording used on screen.
 */
import type { SensitiveDataCounters, SensitiveDataRates } from './schema'

// ---------------------------------------------------------------------------
// Units
// ---------------------------------------------------------------------------

/**
 * The two things this surface counts.
 *
 * Deliberately not extensible by a caller: every figure the API returns is a
 * tally of one or the other, and a third value would mean someone invented a
 * measure the metric dictionary does not define.
 */
export type CountUnit = 'event' | 'finding'

/** Singular and plural nouns for each unit, as rendered beside a figure. */
const UNIT_NOUNS = new Map<CountUnit, { readonly one: string; readonly many: string }>([
  // "action" reads better than "event" to an operator and means the same thing
  // here: §8 counts one event per inspected action. The plural is what appears
  // on screen, so the two must never be the same word across units.
  ['event', { one: 'action', many: 'actions' }],
  ['finding', { one: 'finding', many: 'findings' }],
])

/**
 * The noun rendered immediately after a figure, e.g. `3 findings`.
 *
 * This is the mechanism that makes requirement 1 structural rather than
 * editorial: there is no code path from a counter to the screen that does not
 * pass through here, so a bare number cannot be rendered by omission.
 */
export function measureUnitNoun(unit: CountUnit, value: number): string {
  const nouns = UNIT_NOUNS.get(unit)
  // Unreachable for a `CountUnit`; the fallback exists so a future variant
  // renders visibly wrong rather than silently unlabelled.
  if (!nouns) return 'items'
  return value === 1 ? nouns.one : nouns.many
}

/** A figure together with the unit it is in and the sentence describing it. */
export interface CountMeasure {
  /** The API field this came from. Stable, used as a test id and React key. */
  readonly id: keyof SensitiveDataCounters
  /** Operator-facing name of the measure. */
  readonly label: string
  /** Which of the two things it counts. */
  readonly unit: CountUnit
  /** The value, straight from the response. */
  readonly value: number
  /** Why the measure means what it means, shown beneath or on hover. */
  readonly description: string
}

interface MeasureDefinition {
  readonly label: string
  readonly unit: CountUnit
  readonly description: string
}

/**
 * Every §8 counter, its unit and its operator-facing description.
 *
 * A `Map` rather than an object literal — a wire-supplied key must not resolve
 * `Object.prototype` (AAASM-5109/5190), and the lint rule enforces it.
 */
const MEASURE_DEFINITIONS = new Map<keyof SensitiveDataCounters, MeasureDefinition>([
  [
    'event_count',
    {
      label: 'Actions carrying sensitive data',
      unit: 'event',
      description:
        'One per inspected action that carried at least one finding. The denominator for every action-level rate.',
    },
  ],
  [
    'finding_count',
    {
      label: 'Findings in those actions',
      unit: 'finding',
      description:
        'One per detected item. A single action can carry many, so this is normally larger than the action count and is never interchangeable with it.',
    },
  ],
  [
    'blocked_event_count',
    {
      label: 'Actions blocked',
      unit: 'event',
      description: 'Actions refused outright (verdict `deny`).',
    },
  ],
  [
    'blocked_finding_count',
    {
      label: 'Findings in blocked actions',
      unit: 'finding',
      description:
        'Every finding each refused action carried — an action with three findings that is blocked contributes three.',
    },
  ],
  [
    'redacted_event_count',
    {
      label: 'Actions redacted and forwarded',
      unit: 'event',
      description:
        'Payload rewritten and then forwarded (verdict `scrub`). A blocked action never counts here, however many of its findings were rewritten first.',
    },
  ],
  [
    'redacted_finding_count',
    {
      label: 'Redaction operations performed',
      unit: 'finding',
      description:
        'Transformations the pipeline carried out, across every action including the ones it then blocked. This is not “findings whose redacted form was transmitted” — on a blocked action nothing reached the wire.',
    },
  ],
  [
    'prevented_event_count',
    {
      label: 'Actions with evidence of non-transmission',
      unit: 'event',
      description:
        'Actions meeting all four ADR 0032 §8 prevention conditions. Absence of evidence never satisfies them.',
    },
  ],
  [
    'prevented_finding_count',
    {
      label: 'Findings in those actions',
      unit: 'finding',
      description: 'Every finding carried by an action with evidence of non-transmission.',
    },
  ],
  [
    'inspection_incomplete_event_count',
    {
      label: 'Actions whose inspection did not complete',
      unit: 'event',
      description:
        'The detection pass failed open, failed closed, or answered from a reduced path. These are not clean actions — nothing established what they carried.',
    },
  ],
  [
    'unmeasured_transmission_event_count',
    {
      label: 'Actions with no transmission evidence',
      unit: 'event',
      description:
        'Nothing recorded what happened to the bytes, so these actions could not satisfy the prevention test whatever actually happened to them.',
    },
  ],
])

/** Every measure id, in the order the dictionary defines them. */
export const MEASURE_IDS: readonly (keyof SensitiveDataCounters)[] = [
  ...MEASURE_DEFINITIONS.keys(),
]

/**
 * The action/finding pairs that must always be shown together.
 *
 * Showing one of a pair alone is how "3" ends up under an "actions" heading.
 * A component iterating this cannot render half a pair without deleting an
 * element of the tuple, which is a visible change rather than an omission.
 */
export const MEASURE_PAIRS: readonly (readonly [
  keyof SensitiveDataCounters,
  keyof SensitiveDataCounters,
])[] = [
  ['event_count', 'finding_count'],
  ['blocked_event_count', 'blocked_finding_count'],
  ['redacted_event_count', 'redacted_finding_count'],
  ['prevented_event_count', 'prevented_finding_count'],
]

/** One measure, resolved against a counters block. */
export function countMeasure(
  id: keyof SensitiveDataCounters,
  counters: SensitiveDataCounters,
): CountMeasure {
  const definition = MEASURE_DEFINITIONS.get(id)
  if (!definition) {
    // Unreachable while `id` is keyed to the counters type; kept total so a
    // future counter without a definition renders as unlabelled rather than
    // throwing out of a panel and taking the page with it.
    return {
      id,
      label: id,
      unit: 'event',
      value: counters[id],
      description: 'This counter has no description in the dashboard yet.',
    }
  }
  return { id, ...definition, value: counters[id] }
}

/** Every measure, resolved against a counters block. */
export function countMeasures(counters: SensitiveDataCounters): CountMeasure[] {
  return MEASURE_IDS.map((id) => countMeasure(id, counters))
}

/**
 * A figure and its unit as one string, e.g. `3 findings`.
 *
 * The canonical rendering. `CountFigure` puts the two halves in separate
 * elements for styling, and asserts against this to stay in step.
 */
export function countMeasureText(measure: CountMeasure): string {
  return `${formatCount(measure.value)} ${measureUnitNoun(measure.unit, measure.value)}`
}

/** Thousands-separated, locale-independent so tests and screenshots agree. */
export function formatCount(value: number): string {
  return value.toLocaleString('en-US')
}

/**
 * A rate as a percentage, or the explicit `—` when the API reported none.
 *
 * `null` from the API means the denominator was zero — undefined, not zero.
 * Formatting it as `0%` is the AAASM-5112 defect in one line, so it is not an
 * option this function offers.
 */
export function formatRate(rate: number | null | undefined): string {
  if (rate === null || rate === undefined) return '—'
  const percent = rate * 100
  // One decimal below 10% so a small-but-real share does not round to 0%, which
  // would read as "none" for something that happened.
  const digits = percent > 0 && percent < 10 ? 1 : 0
  return `${percent.toFixed(digits)}%`
}

// ---------------------------------------------------------------------------
// Prevention — the structural zero
// ---------------------------------------------------------------------------

/**
 * How much of the window was in a position to measure prevention at all.
 *
 * The four cases are mutually exclusive and exhaustive over
 * `(event_count, unmeasured_transmission_event_count)`.
 */
export type PreventionReading =
  /** Nothing was inspected, so there was nothing to prevent and nothing to measure. */
  | { readonly kind: 'nothing-inspected' }
  /**
   * Every inspected action lacked transmission evidence. `prevention_rate` is a
   * rate over an unmeasured denominator and says nothing about prevention.
   * This is the state every current build is in (AAASM-5685).
   */
  | {
      readonly kind: 'unmeasured'
      readonly eventCount: number
      readonly unmeasuredCount: number
      readonly preventionRate: number | null | undefined
      readonly unmeasuredRate: number | null | undefined
    }
  /** Some actions carried evidence and some did not. */
  | {
      readonly kind: 'partly-measured'
      readonly eventCount: number
      readonly unmeasuredCount: number
      readonly measuredCount: number
      readonly preventedCount: number
      readonly preventionRate: number | null | undefined
      readonly unmeasuredRate: number | null | undefined
    }
  /** Every inspected action carried transmission evidence. The rate is a measurement. */
  | {
      readonly kind: 'measured'
      readonly eventCount: number
      readonly preventedCount: number
      readonly preventionRate: number | null | undefined
    }

/**
 * Classify a window's prevention figure by how much of it was measurable.
 *
 * Reads `unmeasured_transmission_event_count` rather than inferring from
 * `prevented_event_count === 0`: that predicate is false for many honest reasons
 * — an allowed action, a decision taken after transmission — and only the stored
 * counter means "nothing observed the bytes".
 */
export function readPrevention(
  counters: SensitiveDataCounters,
  rates: SensitiveDataRates,
): PreventionReading {
  const eventCount = counters.event_count
  if (eventCount === 0) return { kind: 'nothing-inspected' }

  const unmeasuredCount = counters.unmeasured_transmission_event_count
  const preventionRate = rates.prevention_rate
  const unmeasuredRate = rates.unmeasured_transmission_rate

  if (unmeasuredCount >= eventCount) {
    return { kind: 'unmeasured', eventCount, unmeasuredCount, preventionRate, unmeasuredRate }
  }
  if (unmeasuredCount > 0) {
    return {
      kind: 'partly-measured',
      eventCount,
      unmeasuredCount,
      measuredCount: eventCount - unmeasuredCount,
      preventedCount: counters.prevented_event_count,
      preventionRate,
      unmeasuredRate,
    }
  }
  return {
    kind: 'measured',
    eventCount,
    preventedCount: counters.prevented_event_count,
    preventionRate,
  }
}

/**
 * The headline figure, which always carries the unmeasured share beside it.
 *
 * The two percentages are rendered as one phrase rather than as two independent
 * statistics because they are only interpretable together: `0% prevented` alone
 * is the false signal, and `0% prevented — 100% unmeasured` is not.
 */
export function preventionHeadline(reading: PreventionReading): string {
  if (reading.kind === 'nothing-inspected') return 'Not measured'
  if (reading.kind === 'measured') {
    return `${formatRate(reading.preventionRate)} prevented — 0% unmeasured`
  }
  return `${formatRate(reading.preventionRate)} prevented — ${formatRate(reading.unmeasuredRate)} unmeasured`
}

/**
 * The badge beside the headline, naming the epistemic state in one word.
 *
 * Not decoration: the headline of a structural zero and of a measured zero
 * differ only in one percentage, and an operator skimming a dashboard reads
 * badges before they read percentages.
 */
export function preventionStatusLabel(reading: PreventionReading): string {
  switch (reading.kind) {
    case 'nothing-inspected':
      return 'Nothing to measure'
    case 'unmeasured':
      return 'Unmeasured'
    case 'partly-measured':
      return 'Partly measured'
    case 'measured':
      return 'Measured'
  }
}

/**
 * The sentence that says what the headline number is evidence of.
 *
 * This is the requirement-2 payload. Its presence is asserted by
 * `PreventionPanel.test.tsx`, and a build that renders the headline without it
 * fails that test — which is the point: the number alone is the untruth.
 */
export function preventionQualifier(reading: PreventionReading): string {
  switch (reading.kind) {
    case 'nothing-inspected':
      return 'No inspected action in this window carried sensitive data, so there was nothing to prevent and nothing to measure. This is not a clean bill of health for the window — it is the absence of anything to report.'
    case 'unmeasured':
      return `Nothing recorded transmission evidence for any of the ${formatCount(reading.eventCount)} inspected ${measureUnitNoun('event', reading.eventCount)}, so prevention could not be measured at all. This figure is an absent measurement, not a measured absence of prevention.`
    case 'partly-measured':
      return `${formatCount(reading.unmeasuredCount)} of ${formatCount(reading.eventCount)} inspected ${measureUnitNoun('event', reading.eventCount)} recorded no transmission evidence, so this figure is measured over the remaining ${formatCount(reading.measuredCount)} only and understates what may have been prevented.`
    case 'measured':
      return `All ${formatCount(reading.eventCount)} inspected ${measureUnitNoun('event', reading.eventCount)} recorded transmission evidence, so this figure is a measurement: ${formatCount(reading.preventedCount)} ${measureUnitNoun('event', reading.preventedCount)} met all four ADR 0032 §8 prevention conditions.`
  }
}

/**
 * Why prevention cannot currently be measured, when it cannot.
 *
 * Returned only for the `unmeasured` reading. It names the ticket so an operator
 * who asks "is this ever going to be a number?" has somewhere to look, rather
 * than concluding the product is failing to prevent anything.
 */
export function preventionCause(reading: PreventionReading): string | null {
  if (reading.kind !== 'unmeasured') return null
  return 'No interception mechanism in this build records what happened to the forwarded bytes, so no action can satisfy the prevention test. Tracked as AAASM-5685.'
}

/**
 * Everything a screen reader is told about prevention, as one sentence.
 *
 * `aria-live` must announce a measured number or the reason there is not one —
 * never an unmeasured all-clear. Composed from the same three pieces the visual
 * panel renders, so the two cannot diverge.
 */
export function preventionAnnouncement(reading: PreventionReading): string {
  const cause = preventionCause(reading)
  return [
    `Prevention: ${preventionStatusLabel(reading)}.`,
    `${preventionHeadline(reading)}.`,
    preventionQualifier(reading),
    cause,
  ]
    .filter((part): part is string => part !== null)
    .join(' ')
}

// ---------------------------------------------------------------------------
// Coverage — a lossy window is not a complete one
// ---------------------------------------------------------------------------

/**
 * Whether every action in the window was actually inspected to completion.
 *
 * `complete: true` asserts only what `inspection_incomplete_event_count` can
 * support: every action the projection holds for this window ran its detection
 * pass to completion. It deliberately does **not** assert that the window holds
 * every action that occurred — no response field reports rotation or loss, and
 * the panel copy says "every recorded action", never "every action".
 */
export interface InspectionCoverage {
  readonly complete: boolean
  readonly incompleteCount: number
  readonly eventCount: number
}

export function readInspectionCoverage(counters: SensitiveDataCounters): InspectionCoverage {
  return {
    complete: counters.inspection_incomplete_event_count === 0,
    incompleteCount: counters.inspection_incomplete_event_count,
    eventCount: counters.event_count,
  }
}

/** The sentence rendered for an inspection-coverage reading. */
export function inspectionCoverageSentence(coverage: InspectionCoverage): string {
  if (coverage.eventCount === 0) {
    return 'No action was inspected in this window, so there is no inspection coverage to report.'
  }
  if (coverage.complete) {
    return `Every one of the ${formatCount(coverage.eventCount)} recorded ${measureUnitNoun('event', coverage.eventCount)} ran its detection pass to completion. This describes the actions the projection holds; no field on this response reports whether the window itself lost any.`
  }
  return `${formatCount(coverage.incompleteCount)} of ${formatCount(coverage.eventCount)} recorded ${measureUnitNoun('event', coverage.eventCount)} did not run their detection pass to completion — they failed open, failed closed, or answered from a reduced path. Every figure on this page counts them as inspected, and nothing established what they carried.`
}

/** How much of a matching set a page of the drill-down list is showing. */
export interface PageCoverage {
  readonly showing: number
  readonly total: number
  readonly truncated: boolean
}

/**
 * Compare a returned page against the total the API reported for the filter.
 *
 * `total` is every matching event in the window, not the length of the page —
 * the API's own doc says a UI pairing the two must label this as the total.
 */
export function readPageCoverage(showing: number, total: number): PageCoverage {
  return { showing, total, truncated: total > showing }
}

/** The sentence rendered above the drill-down list. */
export function pageCoverageSentence(coverage: PageCoverage): string {
  const unit = measureUnitNoun('event', coverage.total)
  if (!coverage.truncated) {
    return `Showing all ${formatCount(coverage.total)} matching ${unit}.`
  }
  return `Showing ${formatCount(coverage.showing)} of ${formatCount(coverage.total)} matching ${unit}. The rest are counted in the figures above but are not on this page — narrow the filters or shorten the window to see them.`
}

// ---------------------------------------------------------------------------
// Empty, zero, and refused are three different facts
// ---------------------------------------------------------------------------

/**
 * What an all-zero window means, which depends on whether anything was filtered.
 *
 * "No sensitive data was seen", "this query returned nothing" and "you cannot
 * see this" are three different facts. The third is an access outcome and lives
 * in `api.ts`; the first two are distinguished here, because only the filter
 * state can tell them apart.
 */
export type ResultReading =
  /** No filter narrowed the window and nothing was found in it. */
  | { readonly kind: 'nothing-recorded' }
  /** Filters were applied and excluded everything. Other actions may exist. */
  | { readonly kind: 'nothing-matched'; readonly activeFilterCount: number }
  /** There are rows. */
  | { readonly kind: 'populated'; readonly eventCount: number }

export function readResult(eventCount: number, activeFilterCount: number): ResultReading {
  if (eventCount > 0) return { kind: 'populated', eventCount }
  if (activeFilterCount > 0) return { kind: 'nothing-matched', activeFilterCount }
  return { kind: 'nothing-recorded' }
}

/** The title rendered for an empty result. */
export function resultTitle(reading: ResultReading): string {
  switch (reading.kind) {
    case 'nothing-recorded':
      return 'No sensitive data recorded in this window'
    case 'nothing-matched':
      return 'No action matched these filters'
    case 'populated':
      return 'Sensitive-data activity'
  }
}

/** The explanation rendered for an empty result. */
export function resultDescription(reading: ResultReading): string {
  switch (reading.kind) {
    case 'nothing-recorded':
      return 'The projection was queried over the whole window with no filters and returned no inspected action carrying sensitive data. That is a real answer about what was recorded — it is not a statement that no sensitive data moved, only that none was recorded moving.'
    case 'nothing-matched':
      return `The projection answered, and none of the ${formatCount(reading.activeFilterCount)} active ${reading.activeFilterCount === 1 ? 'filter' : 'filters'} left anything to show. Other actions may exist in this window — clear a filter to see them.`
    case 'populated':
      return ''
  }
}
