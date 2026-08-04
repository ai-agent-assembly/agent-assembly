// PolicyDraft → Rego-flavoured DSL preview (AAASM-5023).
//
// Renders the in-memory draft as a read-only policy DSL snippet, ported
// verbatim from the hi-fi prototype's `dslFor()` in
// design/v1/hi-fi/policy-editor.jsx. This is a *preview* — a
// human-readable projection of the draft, not the wire format the server
// consumes (that is serializeDraft.ts → YAML). It never round-trips back
// into the draft, so it is derived, pure, and side-effect free.

import type { PolicyDraft } from './types'

/** Render a PolicyDraft as a read-only Rego-flavoured DSL snippet. */
export function dslFor(draft: PolicyDraft): string {
  const lines: string[] = []
  lines.push(
    `policy "${draft.id}" {`,
    `  name    = "${draft.name}"`,
    `  scope   = "${draft.scope}"`,
    `  version = "${draft.version}"`,
    '',
  )
  draft.rules.forEach((rule, i) => {
    const verbs = rule.verb.map((v) => `"${v}"`).join(', ') || '/* none */'
    // condition is a flat AND chain; an empty chain reads as "always".
    const conds = rule.condition.length > 0 ? rule.condition : ['always']
    const condClause = conds.map((c) => `"${c}"`).join(' and ')
    lines.push(
      `  rule R${i + 1} {`,
      `    when   resource == "${rule.resource}" and verb in [${verbs}]`,
      `    if     ${condClause}`,
      `    then   ${rule.action}`,
    )
    if (rule.action === 'narrow' && rule.narrowPaths?.length) {
      rule.narrowPaths.forEach((p) => lines.push(`      narrow_to "${p}"`))
    }
    if (rule.action === 'approval' && rule.approver) {
      lines.push(
        `      approver { who="${rule.approver.who}" n_of_m="${rule.approver.nOfM}" sla="${rule.approver.sla}" }`,
      )
    }
    if (rule.action === 'scrub-then-allow' && rule.scrubFields?.length) {
      const scrubList = rule.scrubFields.map((s) => `"${s}"`).join(', ')
      lines.push(`      scrub [${scrubList}]`)
    }
    if (rule.exceptions?.length) {
      rule.exceptions.forEach((e) => lines.push(`      except "${e}"`))
    }
    if (rule.timeWindow && rule.timeWindow !== 'always') {
      lines.push(`      window "${rule.timeWindow}"`)
    }
    lines.push(`      severity ${rule.severity || 'block'}`, '  }')
    if (i < draft.rules.length - 1) lines.push('')
  })
  lines.push('}')
  return lines.join('\n')
}
