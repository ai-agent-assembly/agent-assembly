#!/usr/bin/env node
/**
 * Guard: `aa_token` is seeded into sessionStorage ONLY (AAASM-4322 / ADR-0028).
 *
 * WHY THIS EXISTS: AAASM-4322 moved the auth JWT out of localStorage as
 * XSS-exfiltration hardening. localStorage is therefore a state production
 * cannot reach — a spec that seeds it asserts against an impossible world, and
 * because such specs sit in the CI gated set, a change *reverting* that
 * hardening would still pass them. The gate would certify the vulnerability.
 * AAASM-5191 is the same class of bug from the other direction.
 *
 * WHY IT IS NOT A GREP: the first version of this guard was
 * `grep -rn "localStorage.setItem('aa_token'"`. Review planted 11 evasions and
 * it caught 3 — `localStorage['aa_token']=`, `localStorage.aa_token=`,
 * `localStorage.setItem(TOKEN_KEY, ...)` and template-literal keys all walked
 * straight past it. Worse, `grep -r` on a missing directory exits 2, which the
 * shell `if` read as "no match" and reported as a pass: a guard that goes green
 * when its target directory is renamed away is precisely the fail-open this PR
 * exists to remove.
 *
 * HOW IT WORKS: it matches the *write shape* rather than a key string — every
 * form of localStorage write — and then requires the key expression to appear
 * in ALLOWED_KEYS below. That inverts the default: a spec writing localStorage
 * under any key nobody has reviewed FAILS, rather than passing because it did
 * not happen to match a pattern someone thought of. Every entry in ALLOWED_KEYS
 * was resolved to its binding by hand.
 *
 * KNOWN LIMIT (stated, not hidden): `opts.key` / `key` are generic names that
 * currently resolve to the theme and onboarding keys. Rebinding one of them to
 * a token-valued constant whose own name contains no "token" substring is not
 * detectable without type resolution. Rule 4 below closes the realistic version
 * of that hole; the rest is code review.
 *
 * sessionStorage is deliberately unconstrained — it is the correct store.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const SPEC_DIR = 'tests/e2e'

/**
 * Key expressions permitted in a localStorage write. Each was traced to its
 * binding: THEME_KEY === 'aa-dashboard-theme', ONBOARDING_COMPLETED_KEY is the
 * wizard's completion flag, 'aa_team_admin' is a Teams RBAC toggle. None is the
 * auth token. Adding an entry here is a deliberate, reviewable act — which is
 * the point.
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

/** Every way to write to localStorage, with optional window./globalThis. prefix. */
const WRITE_PATTERNS = [
  // localStorage.setItem(<key>, ...)
  /(?:(?:window|globalThis|self)\s*\.\s*)?localStorage\s*\.\s*setItem\s*\(\s*([^,]+?)\s*,/g,
  // localStorage[<key>] = ...
  /(?:(?:window|globalThis|self)\s*\.\s*)?localStorage\s*\[\s*([^\]]+?)\s*\]\s*=(?!=)/g,
  // localStorage.<prop> = ...
  /(?:(?:window|globalThis|self)\s*\.\s*)?localStorage\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)/g,
]

/** Methods that are reads/removals, not key-bearing writes. */
const NON_WRITE_PROPS = new Set(['getItem', 'removeItem', 'clear', 'key', 'length'])

/** A key expression that mentions a token is always wrong, allowlisted or not. */
const TOKEN_SHAPED = /token/i

/** Rebinding an allowlisted generic name to something token-shaped. */
const TOKEN_REBIND =
  /\b(?:key|themeKey)\s*[:=]\s*[^,;\n)}]*token[^,;\n)}]*/gi

const failures = []

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
  const st = statSync(SPEC_DIR)
  if (!st.isDirectory()) throw new Error(`${SPEC_DIR} is not a directory`)
  files = walk(SPEC_DIR)
} catch (err) {
  // Fail closed. A missing/unreadable spec tree means the guard verified
  // nothing, which must never be reported as a pass.
  console.error(
    `FAIL: cannot scan ${SPEC_DIR} — ${err.message}\n` +
      `      The guard cannot confirm anything, so this is a failure, not a pass.`,
  )
  process.exit(1)
}

if (files.length === 0) {
  console.error(
    `FAIL: no spec files found under ${SPEC_DIR}. Refusing to report a pass ` +
      `for a scan that examined nothing.`,
  )
  process.exit(1)
}

for (const file of files) {
  const src = readFileSync(file, 'utf8')
  const lineOf = (idx) => src.slice(0, idx).split('\n').length

  for (const pattern of WRITE_PATTERNS) {
    pattern.lastIndex = 0
    let m
    while ((m = pattern.exec(src)) !== null) {
      const rawKey = m[1].trim().replace(/\s+/g, ' ')
      if (NON_WRITE_PROPS.has(rawKey)) continue

      if (TOKEN_SHAPED.test(rawKey)) {
        failures.push(
          `${file}:${lineOf(m.index)}  localStorage write with a token-shaped key: ${rawKey}`,
        )
      } else if (!ALLOWED_KEYS.has(rawKey)) {
        failures.push(
          `${file}:${lineOf(m.index)}  localStorage write with an unreviewed key: ${rawKey}`,
        )
      }
    }
  }

  TOKEN_REBIND.lastIndex = 0
  let r
  while ((r = TOKEN_REBIND.exec(src)) !== null) {
    failures.push(
      `${file}:${lineOf(r.index)}  allowlisted key name rebound to something token-shaped: ${r[0].trim()}`,
    )
  }
}

if (failures.length > 0) {
  console.error('FAIL: aa_token must be seeded into sessionStorage only (AAASM-4322 / ADR-0028).')
  console.error('      localStorage is a state production cannot reach; a spec that seeds it')
  console.error('      would keep passing if that hardening were reverted.\n')
  for (const f of failures) console.error(`  ${f}`)
  console.error(
    `\n  If a new localStorage key is genuinely legitimate, add it to ALLOWED_KEYS in ` +
      `${import.meta.url.replace(/^file:\/\//, '')} with the binding you traced.`,
  )
  process.exit(1)
}

console.log(
  `OK: ${files.length} spec files scanned; every localStorage write uses a reviewed non-token key.`,
)
