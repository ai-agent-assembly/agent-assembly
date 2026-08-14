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
 *
 * `gatewayHealthy` was `installVerified`, which named a claim the step could not
 * support: the probe says nothing about the operator's SDK (AAASM-5132). It is
 * not `gatewayReachable` either — a degraded gateway answers 503 and *is*
 * reachable, so that name would deny an observation we made. What is recorded
 * is narrower and exact: the most recent probe found the gateway answering
 * `status: "ok"`. It tracks the latest probe in both directions, so it can
 * never outlive the observation behind it.
 */
export interface WizardState {
  framework: FrameworkId | null
  gatewayHealthy: boolean
  policyPreset: PolicyPresetId | null
  enrolled: boolean
}

export const EMPTY_STATE: WizardState = {
  framework: null,
  gatewayHealthy: false,
  policyPreset: null,
  enrolled: false,
}
