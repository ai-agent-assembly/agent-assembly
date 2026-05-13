/**
 * Live Ops feature — shared type definitions.
 *
 * `LiveOperation` is the row-level model for the event-stream zone of
 * the Live Ops page (parent AAASM-1282). Status variants mirror the
 * four states called out in the parent ticket's filter-bar spec.
 */

export type OperationStatus = 'running' | 'pending' | 'blocked' | 'completing'

export const OPERATION_STATUSES: readonly OperationStatus[] = [
  'running',
  'pending',
  'blocked',
  'completing',
] as const

/** Step kind inside a live-operation call stack. */
export type CallStackNodeKind = 'llm' | 'tool' | 'result'

/**
 * One step of the mini call-stack rendered inline beneath an
 * expanded `OperationRow`. The tree is a list of root nodes; each
 * node can have nested `children` (e.g. tool calls inside an LLM
 * call) which the renderer walks recursively.
 */
export interface CallStackNode {
  id: string
  kind: CallStackNodeKind
  label: string
  /** Optional latency for this step in milliseconds. */
  latencyMs?: number
  children?: CallStackNode[]
}

export interface LiveOperation {
  /** Stable identifier from the gateway event stream. */
  id: string
  /** Owning agent id (matches `Agent.id` from the fleet view-model). */
  agent: string
  /** Owning team id (the agent's team). Optional until the WS feed wires it. */
  team?: string
  /** Operation verb — e.g. `read`, `write`, `delete`, `exec`. */
  opType: string
  /** Target resource — e.g. `gmail.send`, `pg.users`. */
  resource: string
  /** Lifecycle phase. */
  status: OperationStatus
  /** ISO-8601 timestamp marking when the operation entered the pipeline. */
  startedAt: string
  /** Wall-clock latency observed so far, in milliseconds. */
  latencyMs: number
  /** Optional call-stack tree shown inline when the row is expanded. */
  callStack?: CallStackNode[]
}

/**
 * Filter selection for the Live Ops event-stream zone.
 *
 * `null` / `undefined` on any axis means "no filter on this axis"; all
 * non-null axes are AND-combined when applied to a list of operations.
 * Mirrors the four filter dimensions called out in AAASM-1282 #6.
 */
export interface LiveOpsFilters {
  agent?: string | null
  team?: string | null
  opType?: string | null
  status?: OperationStatus | null
}

/** Convenience sentinel for "no filters active". */
export const EMPTY_FILTERS: LiveOpsFilters = {
  agent: null,
  team: null,
  opType: null,
  status: null,
}
