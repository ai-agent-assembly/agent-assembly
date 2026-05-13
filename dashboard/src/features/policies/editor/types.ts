// Types for the Policy Editor overlay (AAASM-1370).
// Mirrors the hi-fi prototype's mock shape in
// design/v1/hi-fi/policy-editor.jsx.

export type ResourceOption =
  | 'gmail'
  | 'gdrive'
  | 's3'
  | 'pg'
  | 'shell'
  | 'http'
  | 'github'
  | 'slack'

export type VerbOption = 'read' | 'write' | 'delete' | 'exec'

export type ActionKind = 'allow' | 'narrow' | 'approval' | 'scrub-then-allow' | 'deny'

export type ConditionPreset =
  | 'always'
  | 'recipient not in @acme.com'
  | 'host in allowlist'
  | 'path matches customer-pii/*'
  | 'table contains PII columns'
  | '2-person review required'
  | 'amount < $100'
  | 'business hours only'

export type WindowKind =
  | 'always'
  | 'business hours'
  | 'after hours'
  | 'weekdays'
  | 'on-call hours'

export type Severity = 'warn' | 'block'

export type ApproverWho =
  | 'security-oncall'
  | 'data-platform-lead'
  | 'agent-owner'
  | 'sre-rotation'
  | 'finance-head'

export type ApproverQuorum = '1-of-1' | '1-of-2' | '2-of-2' | '2-of-3'

export type ApproverSla = '5m' | '15m' | '30m' | '1h' | '4h' | '24h'

export interface ApproverConfig {
  who: ApproverWho
  nOfM: ApproverQuorum
  sla: ApproverSla
}

export interface RuleDraft {
  /** Local React key — stable across edits to the same rule. */
  id: string
  resource: ResourceOption
  verb: VerbOption[]
  action: ActionKind
  /** Flat AND chain. The prototype does not nest groups. */
  condition: ConditionPreset[]
  /** Only meaningful when action === 'narrow'. */
  narrowPaths?: string[]
  /** Only meaningful when action !== 'allow'. */
  exceptions?: string[]
  /** Only meaningful when action === 'approval'. */
  approver?: ApproverConfig
  /** Only meaningful when action === 'scrub-then-allow'. */
  scrubFields?: string[]
  timeWindow: WindowKind
  severity: Severity
}

export type PolicyStatus = 'active' | 'proposed'

export interface PolicyDraft {
  /** Stable identifier for the policy (e.g. "pol-research-bot"). */
  id: string
  name: string
  scope: string
  version: string
  status: PolicyStatus
  rules: RuleDraft[]
}

export type ValidationSeverity = 'error' | 'warn' | 'info'

export interface ValidationIssue {
  severity: ValidationSeverity
  /** Rule label ("R1", "R2", "—" for policy-level). */
  rule: string
  message: string
}

/** Payload published into OverlayContext when the editor is opened. */
export interface PolicyEditorOverlayProps {
  mode: 'new' | 'edit'
  name?: string
  version?: string
}
