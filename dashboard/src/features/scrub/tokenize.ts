/**
 * Client-side approximation of the gateway's redaction, for the payload preview.
 *
 * It is an *approximation*, not a scan: `aa-security` matches literal prefixes
 * with Aho-Corasick and scores entropy, neither of which a browser regex
 * reproduces. Callers must present its output as a local preview — see
 * `PayloadDiff` — never as what the gateway did to real traffic.
 *
 * Detectors with no `previewRegex` (entropy scoring, policy-authored patterns)
 * are skipped rather than approximated; `UNPREVIEWABLE_DETECTORS` names them so
 * the UI can say which detectors this preview does not stand in for.
 */
import { PREVIEWABLE_DETECTORS } from './detectors'
import type { ScrubDetector, ScrubToken } from './types'

/**
 * Split `text` into plain and redacted spans.
 *
 * `detectors` defaults to the previewable slice of the shipped catalogue, in
 * `AC_PATTERNS` order: a JS alternation is leftmost-first at each position, the
 * same tie-break Aho-Corasick applies by lowest pattern index, so keeping the
 * scanner's order keeps `sk-ant-` winning over `sk-`.
 */
export function tokenize(
  text: string,
  detectors: readonly ScrubDetector[] = PREVIEWABLE_DETECTORS,
): ScrubToken[] {
  const usable = detectors.filter((d) => d.previewRegex !== undefined)
  if (usable.length === 0) {
    return text.length > 0 ? [{ kind: 'plain', text }] : []
  }

  const combined = new RegExp(
    usable.map((d) => `(?<${groupName(d.id)}>${d.previewRegex})`).join('|'),
    'g',
  )

  const tokens: ScrubToken[] = []
  let last = 0
  for (const match of text.matchAll(combined)) {
    const idx = match.index ?? 0
    if (idx > last) {
      tokens.push({ kind: 'plain', text: text.slice(last, idx) })
    }
    const groups = match.groups ?? {}
    const matchedName = Object.keys(groups).find((k) => groups[k] !== undefined)
    const detector = matchedName
      ? usable.find((d) => groupName(d.id) === matchedName)
      : undefined
    if (detector) {
      tokens.push({ kind: 'match', text: match[0], detector })
    } else {
      tokens.push({ kind: 'plain', text: match[0] })
    }
    last = idx + match[0].length
    if (match[0].length === 0) break
  }
  if (last < text.length) {
    tokens.push({ kind: 'plain', text: text.slice(last) })
  }
  return tokens
}

/**
 * Named capture groups must be valid JS identifiers; `CredentialKind` ids
 * already are, but a policy-defined id need not be, so it is sanitised rather
 * than trusted.
 *
 * `\W` is used in its strict sense of `[^A-Za-z0-9_]`, which holds because this
 * literal carries neither the `u`/`v` nor the `i` flag. Adding either is the one
 * change that could alter which characters survive, so a future flag here needs
 * re-checking rather than assuming the classes stay interchangeable. Note this
 * only renames a capture group — it is not part of match-boundary logic, so it
 * cannot move where a detector starts or ends.
 */
function groupName(id: string): string {
  return `d${id.replace(/\W/g, '_')}`
}

export function countMatchesByDetector(tokens: readonly ScrubToken[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const t of tokens) {
    if (t.kind === 'match') {
      counts[t.detector.id] = (counts[t.detector.id] ?? 0) + 1
    }
  }
  return counts
}
