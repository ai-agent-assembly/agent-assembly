/**
 * The dashboard truthfulness contract (AAASM-5173).
 *
 * Page-level lanes import from here. Do not re-declare any of these types or
 * re-derive any of these rules locally — two lanes disagreeing about what
 * "unknown" or "allow" means is exactly the failure this module exists to
 * prevent.
 */
export {
  NO_DATA,
  TRUTH_STATES,
  TRUTH_STATE_META,
  absent,
  certain,
  certainText,
  demo,
  isAbsent,
  isKnown,
  known,
  mapCertain,
  propagateAbsence,
  type AbsentValue,
  type Certain,
  type KnownValue,
  type TruthState,
  type TruthStateMeta,
  type TruthTone,
} from './absence'

export {
  cascadeIsEmpty,
  resolveVerdict,
  tallyVerdicts,
  type CapabilityVerdict,
  type CascadeEvidence,
  type VerdictTally,
} from './verdict'

export { certainFromQuery, type CertainFromQueryOptions, type QueryOutcome } from './query'
