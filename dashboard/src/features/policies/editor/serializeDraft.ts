// PolicyDraft → YAML serializer (AAASM-1371).
//
// Emits the operator-facing schema the server's POST /api/v1/policies
// endpoint accepts, modelled after policy-examples/medium-risk.yaml:
//
//   apiVersion: agent-assembly/v1
//   kind: Policy
//   metadata:
//     name: <draft.name>
//     scope: <draft.scope>
//     version: <draft.version>
//   spec:
//     rules:
//       - id: <derived>
//         description: <human-readable summary of the rule clauses>
//         match:
//           actions: ["<resource>:<verb>", …]
//         effect: <allow | block | require_approval>
//         approval:                          # only when effect = require_approval
//           timeout_seconds: <derived from approver.sla>
//           approvers: [<approver.who>]
//         audit: true
//
// The editor's draft model is richer than the server schema (timeWindow,
// severity, scrubFields, narrowPaths, exceptions, conditions). Where the
// server has no slot for a field, it rides along in the rule's
// `description` so it round-trips through operator inspection — but is
// not enforced by the gateway. Expanding the server schema to enforce
// these fields is filed as a backend follow-up under AAASM-11.

import YAML from 'yaml'
import type {
  ApproverConfig,
  ApproverSla,
  PolicyDraft,
  RuleDraft,
} from './types'

const SLA_TO_SECONDS: Record<ApproverSla, number> = {
  '5m': 300,
  '15m': 900,
  '30m': 1800,
  '1h': 3600,
  '4h': 14400,
  '24h': 86400,
}

type ServerEffect = 'allow' | 'block' | 'require_approval'

function mapEffect(rule: RuleDraft): ServerEffect {
  switch (rule.action) {
    case 'deny':
      return 'block'
    case 'approval':
      return 'require_approval'
    case 'allow':
    case 'narrow':
    case 'scrub-then-allow':
      // narrow + scrub-then-allow degrade to plain allow on the server side;
      // the additional constraints are conveyed via `description` until the
      // backend schema grows first-class support.
      return 'allow'
  }
}

function deriveRuleId(rule: RuleDraft, idx: number): string {
  return `R${idx + 1}-${rule.resource}-${rule.action}`
}

function deriveActions(rule: RuleDraft): string[] {
  return rule.verb.map((verb) => `${rule.resource}:${verb}`)
}

function deriveDescription(rule: RuleDraft): string {
  const parts: string[] = []
  parts.push(
    `when ${rule.resource}:[${rule.verb.join(',') || '(no verbs)'}]`,
  )
  if (rule.condition.length > 0) {
    parts.push(`if [${rule.condition.join(' AND ')}]`)
  }
  parts.push(`then ${rule.action}`)
  if (rule.action === 'narrow' && rule.narrowPaths && rule.narrowPaths.length > 0) {
    parts.push(`narrow to [${rule.narrowPaths.join(', ')}]`)
  }
  if (rule.action === 'scrub-then-allow' && rule.scrubFields && rule.scrubFields.length > 0) {
    parts.push(`scrub [${rule.scrubFields.join(', ')}]`)
  }
  if (rule.exceptions && rule.exceptions.length > 0) {
    parts.push(`except [${rule.exceptions.join(', ')}]`)
  }
  parts.push(`window: ${rule.timeWindow}`)
  parts.push(`severity: ${rule.severity}`)
  return parts.join(' · ')
}

function approvalBlock(
  approver: ApproverConfig | undefined,
): { timeout_seconds: number; approvers: string[] } {
  const config = approver ?? { who: 'security-oncall', nOfM: '1-of-1', sla: '30m' }
  return {
    timeout_seconds: SLA_TO_SECONDS[config.sla],
    approvers: [config.who],
  }
}

interface SerializedRule {
  id: string
  description: string
  match: { actions: string[] }
  effect: ServerEffect
  approval?: { timeout_seconds: number; approvers: string[] }
  audit: true
}

interface SerializedPolicy {
  apiVersion: 'agent-assembly/v1'
  kind: 'Policy'
  metadata: { name: string; scope: string; version: string }
  spec: { rules: SerializedRule[] }
}

function serializeRule(rule: RuleDraft, idx: number): SerializedRule {
  const effect = mapEffect(rule)
  const out: SerializedRule = {
    id: deriveRuleId(rule, idx),
    description: deriveDescription(rule),
    match: { actions: deriveActions(rule) },
    effect,
    audit: true,
  }
  if (effect === 'require_approval') {
    out.approval = approvalBlock(rule.approver)
  }
  return out
}

/** Serialise a PolicyDraft to a deterministic YAML string. */
export function serializeDraft(draft: PolicyDraft): string {
  const policy: SerializedPolicy = {
    apiVersion: 'agent-assembly/v1',
    kind: 'Policy',
    metadata: {
      name: draft.name,
      scope: draft.scope,
      version: draft.version,
    },
    spec: {
      rules: draft.rules.map(serializeRule),
    },
  }
  return YAML.stringify(policy, { lineWidth: 0, indent: 2 })
}
