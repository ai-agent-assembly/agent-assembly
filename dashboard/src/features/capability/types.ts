export type Verb = 'read' | 'write' | 'delete' | 'exec'

export type Decision = 'allow' | 'narrow' | 'approval' | 'deny' | 'na'

/**
 * The decisions an operator may actually record as an override (AAASM-5124).
 *
 * `POST /api/v1/capability/override` rejects `narrow` and `approval` with a 400:
 * the matrix is a projection of a static capability set, which can only ever
 * yield `allow` / `deny` / `na`, so recording either of the other two "would put
 * a decision in the grid that no projection can ever produce or restore". They
 * are decided per action by policy stages the projection does not run.
 *
 * This is deliberately a *subset* of `Decision` rather than a change to it.
 * `Decision` is the display vocabulary and still has five members — cells and
 * the legend are unaffected; only what the override control may submit narrows,
 * because an override the gateway is certain to refuse has no successful path.
 */
export const OVERRIDABLE_DECISIONS = ['allow', 'deny', 'na'] as const

export type OverridableDecision = (typeof OVERRIDABLE_DECISIONS)[number]

export type AgentMode = 'enforce' | 'shadow'

export type AgentStatus = 'active' | 'idle' | 'suspended'

export type ResourceGroup = 'comm' | 'files' | 'data' | 'infra' | 'code'

export interface Resource {
  id: string
  name: string
  /**
   * Absent for tool columns: an MCP tool name is operator-supplied and the
   * gateway classifies it nowhere, so the backend omits the group rather than
   * guessing one (AAASM-5090).
   */
  group?: ResourceGroup
  paths: string[]
}

export type CapCell = Record<Verb, Decision> & { flag?: boolean }

export interface CapabilityAgent {
  id: string
  name: string
  framework: string
  /** Owning team; absent when the agent registered without one. */
  owner?: string
  /**
   * Trust score as an integer on a 0–100 scale, or `null` when unmeasured.
   *
   * Required-but-nullable, mirroring the wire contract (AAASM-5104): the key is
   * always present and is always `null` today — nothing in the gateway computes
   * a score yet (AAASM-5083) — so every consumer must fold it to `—` rather
   * than assume 0.
   */
  trust: number | null
  /**
   * Absent when the agent declared no enforcement-mode override, or declared
   * one this two-value view cannot represent.
   */
  mode?: AgentMode
  status: AgentStatus
  /** ISO 8601 UTC timestamp of the agent's last heartbeat. */
  lastSeen: string
  flagged?: boolean
  note?: string
  caps: Record<string, CapCell>
}

export interface PolicyRule {
  resource: string
  verb: Verb[]
  action: string
  condition: string
}

export interface Policy {
  id: string
  name: string
  version?: string
  scope: string
  status: 'active' | 'proposed' | 'archived'
  /** Absent from the live endpoint — attribution is owned by AAASM-5096. */
  hits24h?: number
  affects: string[]
  rules: PolicyRule[]
}

export interface SampleCall {
  ts: string
  agent: string
  verb: Verb
  resource: string
  detail?: string
  currentDecision: Decision
  proposedDecision?: Decision
  changeType?: 'newly-blocked' | 'narrowed' | 'unchanged' | 'tightened' | 'false-positive'
  fpReason?: string
}

export interface DecisionMeta {
  label: string
  color: string
  bg: string
}

export interface CapabilityMatrix {
  resources: Resource[]
  agents: CapabilityAgent[]
  policies: Policy[]
  sampleCalls: SampleCall[]
}

export interface OverrideRequest {
  agentIds: string[]
  resourceId: string
  verb: Verb
  /**
   * Typed to the accepted subset, not to `Decision`. The optimistic edit the
   * page paints is built from this same request, so a decision the endpoint
   * would refuse cannot reach the grid even for the duration of the round-trip.
   */
  decision: OverridableDecision
}

export interface OverrideResponse {
  updated: CapabilityAgent[]
}

export const VERBS: readonly Verb[] = ['read', 'write', 'delete', 'exec'] as const

// Decision is the closed 5-member app union defined two lines above, not a
// raw wire string — narrow-union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
export const DECISIONS: Record<Decision, DecisionMeta> = {
  allow: { label: 'allow', color: '--ink-3', bg: '--paper-2' },
  narrow: { label: 'narrow', color: '--warn', bg: '--warn-bg' },
  approval: { label: 'approval', color: '--info', bg: '--info-bg' },
  deny: { label: 'deny', color: '--danger', bg: '--danger-bg' },
  na: { label: 'n/a', color: '--ink-5', bg: '--paper-3' },
}
