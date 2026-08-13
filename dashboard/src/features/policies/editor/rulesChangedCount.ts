import type { RuleDraft } from './types'

/**
 * How many rules the operator has actually touched, relative to the snapshot
 * the editor opened with (AAASM-5141).
 *
 * This is the pre-save blast-radius number — the one an operator reads to
 * decide whether simulating is worth it — so it must count edits, not rules.
 * Reporting `draft.rules.length` claimed every rule in the policy was modified
 * the moment any single field changed.
 *
 * Ported from `rulesChangedCount` in `design/v2/hi-fi/policy-editor.jsx`, but
 * keyed by the rule's stable `id` rather than by list position. The mock diffs
 * positionally and adds `abs(length difference)`, which double-counts every
 * rule after a removal from the middle and miscounts a reorder; the shipped
 * editor already carries a stable id per rule (and already builds the snapshot
 * map for the per-rule dirty dot), so identity is available and is what the
 * operator means by "this rule changed".
 *
 * Counts, against the snapshot:
 *  - a surviving rule whose body differs → 1 (same deep-equality-by-JSON test
 *    RuleCard uses for its dirty dot, so the footer total and the visible dots
 *    can never disagree);
 *  - a rule with no snapshot (added or duplicated after open) → 1;
 *  - a snapshot rule no longer in the draft (removed) → 1.
 *
 * Returns 0 when only policy metadata changed (name/scope/status), which is
 * truthful: no rule was modified, so simulate has no rule-level blast radius
 * to preview.
 */
export function rulesChangedCount(
  rules: readonly RuleDraft[],
  originalRuleById: ReadonlyMap<string, RuleDraft>,
): number {
  let changed = 0
  const seen = new Set<string>()

  for (const rule of rules) {
    seen.add(rule.id)
    const original = originalRuleById.get(rule.id)
    if (!original || JSON.stringify(rule) !== JSON.stringify(original)) changed++
  }

  for (const id of originalRuleById.keys()) {
    if (!seen.has(id)) changed++
  }

  return changed
}
