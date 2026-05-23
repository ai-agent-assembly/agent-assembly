import { parseDocument } from 'yaml'

/**
 * The three enforcement modes the gateway recognises. Mirrors the
 * `EnforcementMode` enum in `aa-core/src/policy.rs`. `null` means the
 * YAML doesn't declare a mode — the gateway treats absence as `enforce`.
 */
export type EnforcementMode = 'enforce' | 'observe' | 'disabled'

/**
 * Parse `policy_yaml` and return the `enforcement_mode` field value when
 * present, or `null` when absent / unparseable.
 *
 * Looks at the top-level field first, then `metadata.enforcement_mode` (the
 * envelope form used by some operator-authored policies). Unknown string
 * values fall through to `null` so callers can default safely.
 */
export function extractEnforcementMode(yaml: string): EnforcementMode | null {
  if (!yaml.trim()) return null
  let parsed: unknown
  try {
    parsed = parseDocument(yaml).toJS({ maxAliasCount: 0 }) as unknown
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  const obj = parsed as Record<string, unknown>
  const top = obj['enforcement_mode']
  if (typeof top === 'string' && isEnforcementMode(top)) return top
  const meta = obj['metadata']
  if (typeof meta === 'object' && meta !== null) {
    const nested = (meta as Record<string, unknown>)['enforcement_mode']
    if (typeof nested === 'string' && isEnforcementMode(nested)) return nested
  }
  return null
}

/**
 * Return a copy of `yaml` with its top-level `enforcement_mode` set to
 * `mode`. Preserves existing field ordering, comments, and unrelated keys
 * because we mutate via the `yaml` Document API rather than re-serialising
 * the parsed JS object.
 *
 * If the source YAML is empty or unparseable, returns the input unchanged
 * so callers can fall through their own error handling.
 */
export function withEnforcementMode(yaml: string, mode: EnforcementMode): string {
  if (!yaml.trim()) return yaml
  let doc
  try {
    doc = parseDocument(yaml)
  } catch {
    return yaml
  }
  if (doc.errors.length > 0) return yaml
  doc.set('enforcement_mode', mode)
  return doc.toString()
}

function isEnforcementMode(value: string): value is EnforcementMode {
  return value === 'enforce' || value === 'observe' || value === 'disabled'
}
