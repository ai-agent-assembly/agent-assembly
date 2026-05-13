import type { ScrubPattern, ScrubToken } from './types'

export function tokenize(text: string, patterns: ScrubPattern[]): ScrubToken[] {
  const enabled = patterns.filter((p) => p.enabled)
  if (enabled.length === 0) {
    return text.length > 0 ? [{ kind: 'plain', text }] : []
  }

  const combined = new RegExp(
    enabled.map((p) => `(?<${p.id}>${p.regex})`).join('|'),
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
    const matchedId = Object.keys(groups).find((k) => groups[k] !== undefined)
    const pattern = matchedId ? enabled.find((p) => p.id === matchedId) : undefined
    if (pattern) {
      tokens.push({ kind: 'match', text: match[0], pattern })
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

export function countMatchesByPattern(tokens: ScrubToken[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const t of tokens) {
    if (t.kind === 'match') {
      counts[t.pattern.id] = (counts[t.pattern.id] ?? 0) + 1
    }
  }
  return counts
}
