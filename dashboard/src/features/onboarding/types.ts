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

/**
 * What the wizard has actually observed.
 *
 * There is deliberately no `identity` field: the browser cannot issue one, so an
 * `AgentIdentity` here could only ever hold fabricated key material. Removing it
 * is what makes the AAASM-5179 fiction untypeable rather than merely unrendered.
 */
export interface WizardState {
  framework: FrameworkId | null
  installVerified: boolean
  policyPreset: PolicyPresetId | null
  enrolled: boolean
}

export const EMPTY_STATE: WizardState = {
  framework: null,
  installVerified: false,
  policyPreset: null,
  enrolled: false,
}
