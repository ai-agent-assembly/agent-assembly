// Runtime constants + factory helpers for the Policy Editor (AAASM-1370).
import type {
  ActionKind,
  ApproverQuorum,
  ApproverSla,
  ApproverWho,
  ConditionPreset,
  PolicyDraft,
  ResourceOption,
  RuleDraft,
  Severity,
  VerbOption,
  WindowKind,
} from './types'

export const RES_OPTS = [
  'gmail',
  'gdrive',
  's3',
  'pg',
  'shell',
  'http',
  'github',
  'slack',
] as const satisfies ReadonlyArray<ResourceOption>

export const VERB_OPTS = ['read', 'write', 'delete', 'exec'] as const satisfies ReadonlyArray<VerbOption>

export const ACTION_OPTS: ReadonlyArray<{ id: ActionKind; label: string; hint: string }> = [
  { id: 'allow', label: 'allow', hint: 'pass through' },
  { id: 'narrow', label: 'narrow', hint: 'restrict scope' },
  { id: 'approval', label: 'approval', hint: 'human review' },
  { id: 'scrub-then-allow', label: 'scrub→allow', hint: 'redact PII first' },
  { id: 'deny', label: 'deny', hint: 'block' },
]

export const COND_PRESETS = [
  'always',
  'recipient not in @acme.com',
  'host in allowlist',
  'path matches customer-pii/*',
  'table contains PII columns',
  '2-person review required',
  'amount < $100',
  'business hours only',
] as const satisfies ReadonlyArray<ConditionPreset>

export const WINDOW_OPTS = [
  'always',
  'business hours',
  'after hours',
  'weekdays',
  'on-call hours',
] as const satisfies ReadonlyArray<WindowKind>

export const SEVERITY_OPTS = ['warn', 'block'] as const satisfies ReadonlyArray<Severity>

export const SCRUB_PRESETS = [
  'emails',
  'phone numbers',
  'SSN',
  'credit cards',
  'API keys',
  'IP addresses',
  'names',
] as const

export const APPROVER_WHO_OPTS = [
  'security-oncall',
  'data-platform-lead',
  'agent-owner',
  'sre-rotation',
  'finance-head',
] as const satisfies ReadonlyArray<ApproverWho>

export const APPROVER_QUORUM_OPTS = [
  '1-of-1',
  '1-of-2',
  '2-of-2',
  '2-of-3',
] as const satisfies ReadonlyArray<ApproverQuorum>

export const APPROVER_SLA_OPTS = ['5m', '15m', '30m', '1h', '4h', '24h'] as const satisfies ReadonlyArray<ApproverSla>

export const ENV_OPTS = ['prod', 'staging'] as const

const DEFAULT_NARROW: Record<ResourceOption, string[]> = {
  s3: ['s3://reports/*'],
  http: ['allowlist.acme.io', 'api.internal'],
  gmail: ['gmail/labels/INBOX/*'],
  gdrive: ['gdrive/shared/team-research/*'],
  github: ['github.com/acme/research/*'],
  pg: ['pg.public.reports'],
  shell: ['shell:python report.py'],
  slack: ['slack/channels/research'],
}

/** Returns the suggested initial narrow paths for a freshly-narrowed rule. */
export function defaultNarrowPaths(resource: ResourceOption): string[] {
  return [...DEFAULT_NARROW[resource]]
}

let ruleIdCounter = 0

/** Monotonic local rule id — used only as a React key. */
export function nextRuleId(): string {
  ruleIdCounter += 1
  return `rule-${ruleIdCounter}`
}

export function defaultRule(): RuleDraft {
  return {
    id: nextRuleId(),
    resource: 'gmail',
    verb: ['read'],
    action: 'allow',
    condition: ['always'],
    timeWindow: 'always',
    severity: 'warn',
  }
}

/** Empty draft for the "new policy" path. */
export function emptyDraft(): PolicyDraft {
  return {
    id: 'new-policy',
    name: '',
    scope: 'global',
    version: '0.1.0',
    status: 'proposed',
    rules: [defaultRule()],
  }
}

/** Stub draft for the "edit existing policy" path until ST-5 wires real loading. */
export function stubDraftFromIdentity(name: string, version: string): PolicyDraft {
  return {
    id: `pol-${name}`,
    name,
    scope: 'global',
    version,
    status: 'active',
    rules: [defaultRule()],
  }
}
