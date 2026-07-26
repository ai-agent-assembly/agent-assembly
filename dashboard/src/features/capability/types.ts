export type Verb = 'read' | 'write' | 'delete' | 'exec'

export type Decision = 'allow' | 'narrow' | 'approval' | 'deny' | 'na'

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
  decision: Decision
}

export interface OverrideResponse {
  updated: CapabilityAgent[]
}

export const VERBS: readonly Verb[] = ['read', 'write', 'delete', 'exec'] as const

export const DECISIONS: Record<Decision, DecisionMeta> = {
  allow: { label: 'allow', color: '--ink-3', bg: '--paper-2' },
  narrow: { label: 'narrow', color: '--warn', bg: '--warn-bg' },
  approval: { label: 'approval', color: '--info', bg: '--info-bg' },
  deny: { label: 'deny', color: '--danger', bg: '--danger-bg' },
  na: { label: 'n/a', color: '--ink-5', bg: '--paper-3' },
}
