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

  if (draft.name.trim().length === 0) {
    issues.push({ severity: 'error', rule: '—', message: 'Policy name is required.' })
  }

  if (draft.rules.length === 0) {
    issues.push({
      severity: 'error',
      rule: '—',
      message: 'A policy must declare at least one rule.',
    })
  }

  draft.rules.forEach((rule, idx) => {
    const label = `R${idx + 1}`

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

    if (rule.action === 'approval') {
      if (!rule.approver) {
        issues.push({
          severity: 'error',
          rule: label,
          message: 'Approval action requires an approver configuration.',
        })
      }
    }

    if (rule.action === 'scrub-then-allow') {
      if (!rule.scrubFields || rule.scrubFields.length === 0) {
        issues.push({
          severity: 'error',
          rule: label,
          message: 'Scrub action requires at least one scrub category.',
        })
      }
    }
  })

  // Duplicate resource+verb pairings across rules indicate ambiguous ordering.
  const seen = new Map<string, number>()
  draft.rules.forEach((rule, idx) => {
    for (const verb of rule.verb) {
      const key = `${rule.resource}:${verb}`
      const prior = seen.get(key)
      if (prior !== undefined) {
        issues.push({
          severity: 'warn',
          rule: `R${idx + 1}`,
          message: `Duplicates R${prior + 1} on ${key} — first matching rule wins.`,
        })
      } else {
        seen.set(key, idx)
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
