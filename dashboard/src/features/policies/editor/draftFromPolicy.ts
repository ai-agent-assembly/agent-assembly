// Map a real `PolicyResponse` into an editable `PolicyDraft` (AAASM-5059).
//
// Replaces the old `stubDraftFromIdentity`, which fabricated a fixed
// gmail/read/allow rule, forced status to "active", and so suppressed the
// draft callout even for a proposed multi-rule policy.
//
// The gateway's `PolicyResponse` carries the raw `policy_yaml`, so we recover
// the real scope + rules from it when the body is in the editor's own
// `spec.rules` schema (exactly what `serializeDraft` writes). Policies
// authored outside the visual editor (section-based tool policies) or whose
// snapshot is not retrievable (empty `policy_yaml`) cannot be mapped to editor
// rules — for those we load what IS known (name / status / scope / rule_count)
// and mark each rule body `unknown` rather than inventing a fake default.

import { parseDocument } from 'yaml'
import type { components } from '../../../api/generated/schema'
import { RES_OPTS, VERB_OPTS, nextRuleId } from './constants'
import type {
  ActionKind,
  ApproverConfig,
  ApproverSla,
  ApproverWho,
  PolicyDraft,
  ResourceOption,
  RuleDraft,
  VerbOption,
} from './types'

type PolicyResponse = components['schemas']['PolicyResponse']

// Inverse of serializeDraft's SLA_TO_SECONDS. Unrecognised timeouts fall back
// to the editor's default SLA so the approver row still renders a valid value.
const SECONDS_TO_SLA: Record<number, ApproverSla> = {
  300: '5m',
  900: '15m',
  1800: '30m',
  3600: '1h',
  14400: '4h',
  86400: '24h',
}

function isResourceOption(value: string): value is ResourceOption {
  return (RES_OPTS as readonly string[]).includes(value)
}

function isVerbOption(value: string): value is VerbOption {
  return (VERB_OPTS as readonly string[]).includes(value)
}

/** A placeholder rule whose real body couldn't be recovered from the YAML. */
function unknownRule(): RuleDraft {
  return {
    id: nextRuleId(),
    resource: 'gmail',
    verb: [],
    action: 'allow',
    condition: [],
    timeWindow: 'always',
    severity: 'warn',
    unknown: true,
  }
}

function effectToAction(effect: unknown): ActionKind {
  // narrow / scrub-then-allow both serialize down to `allow` on the server
  // (serializeDraft.mapEffect), so they cannot be distinguished on the way
  // back — they load as plain allow. deny / approval round-trip faithfully.
  if (effect === 'block') return 'deny'
  if (effect === 'require_approval') return 'approval'
  return 'allow'
}

function approverFrom(approval: unknown): ApproverConfig | undefined {
  if (typeof approval !== 'object' || approval === null) return undefined
  const block = approval as Record<string, unknown>
  const approvers = block['approvers']
  const who =
    Array.isArray(approvers) && typeof approvers[0] === 'string'
      ? (approvers[0] as ApproverWho)
      : 'security-oncall'
  const timeout = block['timeout_seconds']
  const sla = typeof timeout === 'number' ? (SECONDS_TO_SLA[timeout] ?? '30m') : '30m'
  return { who, nOfM: '1-of-1', sla }
}

/** Map one `spec.rules[]` entry (editor schema) into a RuleDraft. */
function ruleFromYaml(raw: unknown): RuleDraft {
  if (typeof raw !== 'object' || raw === null) return unknownRule()
  const entry = raw as Record<string, unknown>

  const match = entry['match']
  const actions =
    typeof match === 'object' && match !== null
      ? (match as Record<string, unknown>)['actions']
      : undefined
  if (!Array.isArray(actions) || actions.length === 0) return unknownRule()

  const pairs = actions
    .filter((a): a is string => typeof a === 'string')
    .map((a) => a.split(':'))
  const first = pairs[0]
  if (!first || !isResourceOption(first[0])) return unknownRule()

  const resource = first[0]
  const verb = pairs
    .filter((p) => p[0] === resource && typeof p[1] === 'string' && isVerbOption(p[1]))
    .map((p) => p[1] as VerbOption)

  const action = effectToAction(entry['effect'])
  const rule: RuleDraft = {
    id: nextRuleId(),
    resource,
    verb,
    // Conditions ride in the free-text `description` only, so they can't be
    // recovered structurally — default to the neutral "applies universally".
    condition: ['always'],
    action,
    timeWindow: 'always',
    severity: 'warn',
  }
  if (action === 'approval') {
    const approver = approverFrom(entry['approval'])
    if (approver) rule.approver = approver
  }
  return rule
}

function scopeFromDoc(doc: Record<string, unknown> | null): string {
  const meta = doc?.['metadata']
  if (typeof meta === 'object' && meta !== null) {
    const scope = (meta as Record<string, unknown>)['scope']
    if (typeof scope === 'string' && scope.trim().length > 0) return scope.trim()
  }
  return 'global'
}

/**
 * Build an editable draft from the real policy the list already holds. Status
 * reflects `policy.active` (so a proposed policy shows the draft callout and a
 * `proposed` status chip); scope + rules come from `policy_yaml`.
 */
export function draftFromPolicy(policy: PolicyResponse): PolicyDraft {
  let doc: Record<string, unknown> | null = null
  const yaml = policy.policy_yaml?.trim()
  if (yaml) {
    try {
      const parsed = parseDocument(yaml).toJS({ maxAliasCount: 0 }) as unknown
      if (typeof parsed === 'object' && parsed !== null) {
        doc = parsed as Record<string, unknown>
      }
    } catch {
      doc = null
    }
  }

  const spec = doc?.['spec']
  const specRules =
    typeof spec === 'object' && spec !== null
      ? (spec as Record<string, unknown>)['rules']
      : undefined

  let rules: RuleDraft[]
  if (Array.isArray(specRules) && specRules.length > 0) {
    rules = specRules.map(ruleFromYaml)
  } else {
    // Body not recoverable from the editor schema — surface `rule_count`
    // placeholders (at least one so the "policy has no rules" error doesn't
    // fire against a real policy), each clearly marked unknown.
    const count = Math.max(1, policy.rule_count ?? 1)
    rules = Array.from({ length: count }, unknownRule)
  }

  return {
    id: `pol-${policy.name}`,
    name: policy.name,
    scope: scopeFromDoc(doc),
    version: policy.version,
    status: policy.active ? 'active' : 'proposed',
    rules,
  }
}
