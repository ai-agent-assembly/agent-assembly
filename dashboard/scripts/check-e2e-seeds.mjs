#!/usr/bin/env node
/**
 * Guard: the auth token is written to sessionStorage ONLY (AAASM-4322).
 *
 * Contract and rationale: dashboard/tests/e2e/README.md, "CI gate".
 *
 * WHY THIS EXISTS: AAASM-4322 moved the auth JWT out of localStorage as
 * XSS-exfiltration hardening. localStorage is therefore a state production
 * cannot reach — a spec that seeds it asserts against an impossible world, and
 * because such specs sit in the CI gated set, a change *reverting* that
 * hardening would still pass them. The gate would certify the vulnerability.
 *
 * ── Why it is not a grep ────────────────────────────────────────────────────
 * v1 was `grep -rn "localStorage.setItem('aa_token'"`. Review planted 11
 * evasions and it caught 3; bracket access, property assignment, constant
 * indirection and template-literal keys all walked past. `grep -r` on a missing
 * directory also exits 2, which the shell `if` read as "no match" and reported
 * as a pass — a guard that goes green when its target tree is renamed away.
 *
 * ── Why matching write shapes was still not enough ──────────────────────────
 * v2 modelled the write shapes and allowlisted the keys. Review then found the
 * asymmetry that mattered: **the fail-closed inversion applied to keys, not to
 * shapes.** An unrecognised *key* failed; an unrecognised *write shape* was
 * never matched by any pattern, so the allowlist check never ran and it failed
 * OPEN. Five further forms genuinely wrote the token past it, and the two that
 * mattered most needed no intent to evade at all — `localStorage?.setItem(...)`
 * is idiomatic defensive style, and `const ls = localStorage` is ordinary
 * refactoring of a long global.
 *
 * v3 (this) inverts the default for shapes too: **every `localStorage`
 * occurrence in executable code must be consumed by a modelled pattern.**
 * Anything unconsumed fails as an unmodelled access. Adding a new access form
 * therefore requires teaching this file about it — the same deliberate,
 * reviewable act that adding a new key already required.
 *
 * sessionStorage is deliberately unconstrained: it is the correct store.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const SPEC_DIR = 'tests/e2e'

/**
 * Key expressions permitted in a localStorage write. Each was traced to its
 * binding: THEME_KEY === 'aa-dashboard-theme', ONBOARDING_COMPLETED_KEY is the
 * onboarding wizard's completion flag, 'aa_team_admin' is a Teams RBAC toggle
 * (see AAASM-5253 — filed separately; not this guard's business). None is the
 * auth token. Adding an entry is a deliberate, reviewable act, which is the point.
 */
const ALLOWED_KEYS = new Set([
  "'aa-dashboard-theme'",
  "'aa_team_admin'",
  'THEME_KEY',
  'ONBOARDING_COMPLETED_KEY',
  'opts.key',
  'opts.themeKey',
  'key',
])

/** Optional global prefix: `window.` / `globalThis.` / `self.`, incl. `?.`. */
const P = String.raw`(?:(?:window|globalThis|self)\s*(?:\?\.|\.)\s*)?`
/** Member access, plain or optional-chained. */
const A = String.raw`(?:\?\.|\.)\s*`
/** Assignment operators that write: `=`, `??=`, `||=`, `&&=`. */
const ASSIGN = String.raw`(?:\?\?|\|\||&&)?=(?!=)`

/**
 * Writes. Group 1 is the key expression, which is allowlist-checked.
 *
 * `builtinsAreNotKeys` applies only to the bare-property form: there,
 * `localStorage.length` names a Storage built-in rather than a user key, and
 * READ_PATTERNS owns it. It must NOT apply to `setItem(<key>, …)`, where an
 * identifier that happens to collide with a built-in name — `key` is a real
 * allowlisted parameter in `onboarding-design-fidelity` — is a genuine key.
 * Conflating the two made a legitimate call look unconsumed.
 */
const WRITE_PATTERNS = [
  { re: new RegExp(`${P}localStorage\\s*${A}setItem\\s*\\(\\s*([^,]+?)\\s*,`, 'g'), builtinsAreNotKeys: false },
  { re: new RegExp(`${P}localStorage\\s*(?:\\?\\.)?\\s*\\[\\s*([^\\]]+?)\\s*\\]\\s*${ASSIGN}`, 'g'), builtinsAreNotKeys: false },
  { re: new RegExp(`${P}localStorage\\s*${A}([A-Za-z_$][\\w$]*)\\s*${ASSIGN}`, 'g'), builtinsAreNotKeys: true },
]

/** Reads and removals — modelled so they are consumed; no key check applies. */
const READ_PATTERNS = [
  new RegExp(`${P}localStorage\\s*${A}(?:getItem|removeItem|clear|key)\\s*\\(`, 'g'),
  new RegExp(`${P}localStorage\\s*${A}length\\b`, 'g'),
]

/** Built-ins that are not user keys when seen through the property-assign pattern. */
const NON_WRITE_PROPS = new Set(['getItem', 'setItem', 'removeItem', 'clear', 'key', 'length'])

/** A key expression mentioning a token is always wrong, allowlisted or not. */
const TOKEN_SHAPED = /token/i

/**
 * Rebinding an allowlisted generic name to something token-shaped. This is what
 * stops `key`/`opts.key` — allowlisted because they currently resolve to the
 * theme and onboarding keys — from being repointed at the auth token.
 *
 * Runs against `noComments`, NOT `codeOnly`: the rebind people actually write is
 * a string literal (`key = 'aa_token'`), and `codeOnly` blanks those. v3 had it
 * on the wrong buffer and silently stopped catching the only form that matters.
 *
 * KNOWN LIMIT, verified: it matches on the *text* of the right-hand side, so it
 * catches `key = 'aa_token'`, `{ key: 'aa_token' }` and `{ key: TOKEN_KEY }` —
 * but not a rebind laundered through a constant whose own name lacks "token".
 *
 * Reaching the gap takes BOTH conditions, which is easy to get wrong when
 * writing the example (an earlier draft of this comment illustrated it with a
 * snippet that is in fact caught):
 *
 *   1. the key expression must itself be allowlisted, or the ALLOWED_KEYS check
 *      rejects it before TOKEN_REBIND is reached — an inline `{ key: AUTH }.key`
 *      is NOT allowlisted, so that form IS caught; and
 *   2. the value must reach it via a name containing no "token" text.
 *
 * Both together, verified not caught:
 *
 *   const AUTH = 'aa_token'
 *   const opts = { key: AUTH }              // `opts.key` IS allowlisted
 *   localStorage.setItem(opts.key, v)       // NOT caught
 *
 * Closing that needs value resolution, i.e. a type-aware pass, which is more
 * machinery than this guard is worth. Code review covers it. Stated here so the
 * gap is a known quantity rather than a discovered one.
 */
const TOKEN_REBIND = /\b(?:key|themeKey)\s*[:=]\s*[^,;\n)}]*token[^,;\n)}]*/gi

/** Reaching the global by computed string name, e.g. `window['localStorage']`. */
const COMPUTED_GLOBAL = /['"`]localStorage['"`]/g

/**
 * Blank out comments — and optionally string/template literals — replacing each
 * character with a space so byte offsets and line numbers survive. Template
 * substitutions (`${...}`) are deliberately left live: they are executable code.
 */
function mask(src, { strings }) {
  const out = src.split('')
  const n = src.length
  let i = 0
  let templDepth = 0

  const blank = (from, to) => {
    for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' '
  }
  const scanTemplateChunk = (from) => {
    let j = from
    while (j < n) {
      if (src[j] === '\\') {
        j += 2
        continue
      }
      if (src[j] === '`') break
      if (src[j] === '$' && src[j + 1] === '{') break
      j++
    }
    return j
  }

  while (i < n) {
    const c = src[i]
    const d = src[i + 1]

    if (c === '/' && d === '/') {
      let j = i
      while (j < n && src[j] !== '\n') j++
      blank(i, j)
      i = j
      continue
    }
    if (c === '/' && d === '*') {
      let j = i + 2
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++
      j = Math.min(j + 2, n)
      blank(i, j)
      i = j
      continue
    }
    if (c === "'" || c === '"') {
      let j = i + 1
      while (j < n && src[j] !== c) {
        if (src[j] === '\\') j++
        j++
      }
      j = Math.min(j + 1, n)
      if (strings) blank(i, j)
      i = j
      continue
    }
    if (c === '`') {
      const j = scanTemplateChunk(i + 1)
      if (strings) blank(i, Math.min(j, n))
      if (j < n && src[j] === '$') {
        templDepth++
        i = j + 2
        continue
      }
      i = Math.min(j + 1, n)
      continue
    }
    if (c === '}' && templDepth > 0) {
      templDepth--
      const j = scanTemplateChunk(i + 1)
      if (strings) blank(i + 1, Math.min(j, n))
      if (j < n && src[j] === '$') {
        templDepth++
        i = j + 2
        continue
      }
      i = Math.min(j + 1, n)
      continue
    }
    i++
  }
  return out.join('')
}

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else if (/\.(ts|tsx|mts|cts|js|mjs|cjs)$/.test(entry)) out.push(full)
  }
  return out
}

let files
try {
  if (!statSync(SPEC_DIR).isDirectory()) throw new Error(`${SPEC_DIR} is not a directory`)
  files = walk(SPEC_DIR)
} catch (err) {
  console.error(
    `FAIL: cannot scan ${SPEC_DIR} — ${err.message}\n` +
      `      The guard cannot confirm anything, so this is a failure, not a pass.`,
  )
  process.exit(1)
}

if (files.length === 0) {
  console.error(
    `FAIL: no spec files found under ${SPEC_DIR}. Refusing to report a pass for a ` +
      `scan that examined nothing.`,
  )
  process.exit(1)
}

const failures = []

for (const file of files) {
  const src = readFileSync(file, 'utf8')
  // WHICH BUFFER, AND WHY — v3 got this wrong and it cost three detections.
  //
  //   noComments  comments blanked, STRING LITERALS INTACT.
  //   codeOnly    comments AND string literals blanked.
  //
  // Everything that inspects a *key* or a *value* must read `noComments`, because
  // keys are string literals — blanking them makes `key = 'aa_token'` look like
  // `key = ` and a rebind becomes invisible. v3 ran TOKEN_REBIND against
  // `codeOnly` and so could not see a literal rebind, which is the only way
  // anyone would write one; it also hid `addInitScript("localStorage.setItem(
  // 'aa_token', …)")`, where the whole write lives inside a string.
  //
  // Only the unconsumed-occurrence sweep reads `codeOnly`, and only because
  // spec *prose* legitimately says "localStorage" — in comments (blanked in
  // both) and in test-name strings such as
  // `test('explicit choice persists across reload (localStorage)')`, which
  // would otherwise be flagged. Narrow exception, narrow buffer.
  //
  // Both masks preserve length, so offsets and line numbers are interchangeable.
  const codeOnly = mask(src, { strings: true })
  const noComments = mask(src, { strings: false })
  const lineOf = (idx) => src.slice(0, idx).split('\n').length

  /** Character ranges consumed by a modelled pattern. */
  const consumed = []

  for (const { re, builtinsAreNotKeys } of WRITE_PATTERNS) {
    re.lastIndex = 0
    let m
    while ((m = re.exec(noComments)) !== null) {
      const masked = m[1].trim().replace(/\s+/g, ' ')
      if (builtinsAreNotKeys && NON_WRITE_PROPS.has(masked)) continue // READ_PATTERNS owns it
      consumed.push([m.index, m.index + m[0].length])

      // Recover the real key: masking blanked string contents, so read it back
      // from the original source over the same span.
      const span = src.slice(m.index, m.index + m[0].length)
      const found = span.match(/\(\s*([^,]+?)\s*,|\[\s*([^\]]+?)\s*\]/)
      const key = ((found && (found[1] ?? found[2])) || masked).trim().replace(/\s+/g, ' ')

      if (TOKEN_SHAPED.test(key)) {
        failures.push(`${file}:${lineOf(m.index)}  localStorage write with a token-shaped key: ${key}`)
      } else if (!ALLOWED_KEYS.has(key)) {
        failures.push(`${file}:${lineOf(m.index)}  localStorage write with an unreviewed key: ${key}`)
      }
    }
  }

  for (const pattern of READ_PATTERNS) {
    pattern.lastIndex = 0
    let m
    while ((m = pattern.exec(noComments)) !== null) consumed.push([m.index, m.index + m[0].length])
  }

  // ── The shape inversion ──────────────────────────────────────────────────
  // Any mention of localStorage in executable code that no modelled pattern
  // consumed is an access form this guard does not understand. Failing it is
  // the point: an unmodelled shape must not pass merely because nobody thought
  // to write a pattern for it. This is what closes aliasing (`const ls =
  // localStorage`), optional chaining, `Object.assign(localStorage, …)` and
  // destructuring in one move.
  const occ = /\blocalStorage\b/g
  let o
  while ((o = occ.exec(codeOnly)) !== null) {
    if (!consumed.some(([s, e]) => o.index >= s && o.index < e)) {
      failures.push(
        `${file}:${lineOf(o.index)}  unmodelled localStorage access — the key cannot be ` +
          `verified here. Use a direct localStorage.setItem(...) call, or teach ` +
          `WRITE_PATTERNS/READ_PATTERNS about the form.`,
      )
    }
  }

  COMPUTED_GLOBAL.lastIndex = 0
  let g
  while ((g = COMPUTED_GLOBAL.exec(noComments)) !== null) {
    failures.push(
      `${file}:${lineOf(g.index)}  localStorage reached by computed string name — use the ` +
        `identifier directly so the key can be checked.`,
    )
  }

  TOKEN_REBIND.lastIndex = 0
  let r
  while ((r = TOKEN_REBIND.exec(noComments)) !== null) {
    failures.push(
      `${file}:${lineOf(r.index)}  allowlisted key name rebound to something token-shaped: ${r[0].trim()}`,
    )
  }
}

if (failures.length > 0) {
  console.error('FAIL: the auth token must be written to sessionStorage only (AAASM-4322).')
  console.error('      localStorage is a state production cannot reach; a spec that seeds it')
  console.error('      would keep passing if that hardening were reverted.\n')
  for (const f of [...new Set(failures)]) console.error(`  ${f}`)
  console.error(
    `\n  A legitimate new key goes in ALLOWED_KEYS; a legitimate new access form goes in ` +
      `WRITE_PATTERNS/READ_PATTERNS. Both live in scripts/check-e2e-seeds.mjs — add either ` +
      `with the binding you traced.`,
  )
  process.exit(1)
}

console.log(
  `OK: ${files.length} spec files scanned; every localStorage access is a modelled form ` +
    `with a reviewed non-token key.`,
)
