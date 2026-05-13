export type StepId = 'framework' | 'install' | 'identity' | 'policy' | 'enroll'

export interface StepMeta {
  id: StepId
  num: string
  label: string
}

export type FrameworkId = 'langchain' | 'autogen' | 'crewai' | 'custom'

export interface Framework {
  id: FrameworkId
  name: string
  glyph: string
  sub: string
  popular: boolean
}

export type PolicyPresetId = 'default-deny' | 'read-only' | 'monitor-only'

export type PolicyRisk = 'low' | 'medium' | 'high'

export interface PolicyPreset {
  id: PolicyPresetId
  name: string
  sub: string
  desc: string
  blocks: ReadonlyArray<string>
  allows: ReadonlyArray<string>
  risk: PolicyRisk
}

export interface AgentIdentity {
  did: string
  alg: string
  fingerprint: string
  issuedAt: string
}

export interface WizardState {
  framework: FrameworkId | null
  installVerified: boolean
  identity: AgentIdentity | null
  policyPreset: PolicyPresetId | null
  enrolled: boolean
}

export const EMPTY_STATE: WizardState = {
  framework: null,
  installVerified: false,
  identity: null,
  policyPreset: null,
  enrolled: false,
}
