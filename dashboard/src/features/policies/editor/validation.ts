// Pure validation for a PolicyDraft (AAASM-1370).
// The Validation panel renders the result; the Save button is enabled only
// when there are no errors (warns/infos do not block).

import type { PolicyDraft, ValidationIssue } from './types'

/**
 * Returns a list of validation issues for the supplied draft, in the order
 * they apply: policy-level issues first, then per-rule issues numbered
 * "R1", "R2", …
 */
export function validate(draft: PolicyDraft): ValidationIssue[] {
  const issues: ValidationIssue[] = []

  // Note: the design spec's `validate` (design/v1/hi-fi/policy-editor.jsx
  // :384-407) has no policy-name check — name is not required client-side —
  // so there is deliberately no "Policy name is required." error here.

  if (draft.rules.length === 0) {
    issues.push({
      severity: 'error',
      rule: '—',
      message: 'A policy must declare at least one rule.',
    })
  }

  draft.rules.forEach((rule, idx) => {
    const label = `R${idx + 1}`

    // A rule loaded read-only from an unparseable policy body has no editable
    // fields to validate — skip it (it still counts toward rules.length so the
    // "no rules" error doesn't fire against a real policy). See AAASM-5059.
    if (rule.unknown) return

    if (rule.verb.length === 0) {
      issues.push({
        severity: 'error',
        rule: label,
        message: 'Select at least one verb.',
      })
    }

    if (rule.condition.length === 0) {
      issues.push({
        severity: 'warn',
        rule: label,
        message: 'No conditions — rule applies universally.',
      })
    }

    if (rule.action === 'narrow') {
      if (!rule.narrowPaths || rule.narrowPaths.length === 0) {
        issues.push({
          severity: 'error',
          rule: label,
          message: 'Narrow action requires at least one allow-list path.',
        })
      }
    }

    // Approval intentionally has no approver-required error: the editor shows a
    // default approver (SubClauses.DEFAULT_APPROVER) and serializeDraft
    // materialises that same default into the saved YAML, so an approval rule
    // is always valid. The old error was a false positive (AAASM-5060) — it
    // fired despite the shown, saved default.

    if (rule.action === 'scrub-then-allow') {
      if (!rule.scrubFields || rule.scrubFields.length === 0) {
        // Downgraded from error to warn per the design spec: a scrub with no
        // fields is a full passthrough, not an invalid policy (AAASM-5060).
        issues.push({
          severity: 'warn',
          rule: label,
          message: 'Scrub action with no fields — allows everything through unredacted.',
        })
      }
    }

    if (rule.action === 'deny' && (rule.exceptions?.length ?? 0) > 4) {
      issues.push({
        severity: 'info',
        rule: label,
        message: `${rule.exceptions?.length ?? 0} exceptions on a deny rule — consider narrow instead.`,
      })
    }
  })

  // Duplicate resource+verb pairings across rules indicate ambiguous ordering.
  const seen = new Map<string, number>()
  draft.rules.forEach((rule, idx) => {
    for (const verb of rule.verb) {
      const key = `${rule.resource}:${verb}`
      const prior = seen.get(key)
      if (prior === undefined) {
        seen.set(key, idx)
      } else {
        issues.push({
          severity: 'warn',
          rule: `R${idx + 1}`,
          message: `Duplicates R${prior + 1} on ${key} — first matching rule wins.`,
        })
      }
    }
  })

  return issues
}

export function countBySeverity(issues: ValidationIssue[]) {
  let errors = 0
  let warns = 0
  let infos = 0
  for (const i of issues) {
    if (i.severity === 'error') errors += 1
    else if (i.severity === 'warn') warns += 1
    else infos += 1
  }
  return { errors, warns, infos }
}
