export type Verb = 'read' | 'write' | 'delete' | 'exec'

export type Decision = 'allow' | 'narrow' | 'approval' | 'deny' | 'na'

export type AgentMode = 'enforce' | 'shadow'

export type AgentStatus = 'active' | 'idle' | 'suspended'

export interface Resource {
  id: string
  name: string
  group: 'comm' | 'files' | 'data' | 'infra' | 'code'
  paths: string[]
}

export type CapCell = Record<Verb, Decision> & { flag?: boolean }

export interface CapabilityAgent {
  id: string
  name: string
  framework: string
  owner: string
  trust: number
  mode: AgentMode
  status: AgentStatus
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
  version: string
  scope: string
  status: 'active' | 'proposed' | 'archived'
  hits24h: number
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
