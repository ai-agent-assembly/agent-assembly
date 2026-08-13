// Contrast floor for the nav rail (AAASM-5134 / ADR-0027).
//
// The rail palette comes from the authoritative hi-fi mock, and the mock
// specified a group-heading grey that fails WCAG 2.1 AA. ADR-0027 records that
// the accessibility floor overrides the visual spec, so this test is the
// enforcement: it re-derives the contrast ratio from the *shipped* token and
// fails if a future palette edit drops back below the floor.
//
// It lives in the unit suite on purpose. The obvious home would be
// tests/e2e/theme-visual.spec.ts, which already reasons about the rail in both
// themes — but no CI job runs the dashboard Playwright suite at all, so a check
// placed there would never execute.
//
// The ratio is asserted, not the hex: a later redesign is free to move the
// colour anywhere that stays compliant.
import { describe, expect, it } from 'vitest'
// `?raw` rather than a normal import: the assertion is about the literal token
// values the stylesheet ships, which a bundled CSS import would not expose.
// Same pattern as OverviewPage.test.tsx.
import CSS from './AppShell.css?raw'
import GLOBAL_CSS from '../styles.css?raw'

/** Read a custom property's value out of the shipped stylesheet. */
function token(name: string): string {
  const match = new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`).exec(CSS)
  if (!match?.[1]) throw new Error(`token ${name} not found in AppShell.css`)
  return match[1].toLowerCase()
}

type Theme = 'light' | 'dark'

const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** The declaration block of a top-level rule in the global sheet, by selector. */
function globalRuleBody(selector: string): string {
  const start = GLOBAL_CSS.indexOf(`\n${selector} {`)
  if (start === -1) throw new Error(`rule ${selector} not found`)
  const end = GLOBAL_CSS.indexOf('\n}', start)
  return GLOBAL_CSS.slice(start, end)
}

/** Resolve a global token to the hex the given theme ships. */
function themeToken(name: string, theme: Theme): string {
  const body = globalRuleBody(theme === 'light' ? ':root' : ':root[data-theme="dark"]')
  const match = new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`).exec(body)
  if (!match?.[1]) throw new Error(`token ${name} not found in the ${theme} palette`)
  return match[1].toLowerCase()
}

/** The custom property a rule in AppShell.css points `property` at. */
function referencedToken(selector: string, property: string): string {
  const start = CSS.indexOf(`\n${selector} {`)
  if (start === -1) throw new Error(`rule ${selector} not found in AppShell.css`)
  const body = CSS.slice(start, CSS.indexOf('\n}', start))
  const match = new RegExp(`${property}:\\s*var\\((--[a-z0-9-]+)\\)`).exec(body)
  if (!match?.[1]) throw new Error(`${selector} has no ${property}: var(--…)`)
  return match[1]
}

/** WCAG 2.1 relative luminance over sRGB. */
function luminance(hex: string): number {
  const channel = (n: number) => {
    const c = n / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi! + 0.05) / (lo! + 0.05)
}

/** WCAG 2.1 AA, normal text. Rail text is 11px — the 3:1 large-text exemption does not apply. */
const AA_NORMAL_TEXT = 4.5

/**
 * The dark-mode rail ground specified by design/v2.
 *
 * The dashboard keeps the rail identical in both themes, so `--shell-nav-bg` is
 * the ground that actually ships. This darker value is asserted alongside it so
 * the token stays compliant if the shipped rail is ever aligned to v2's
 * dark-mode ground — a darker ground only raises the ratio, so passing here
 * proves the floor holds in both themes.
 */
const V2_DARK_RAIL_BG = '#0a0907'

describe('nav rail contrast floor (ADR-0027)', () => {
  it('renders group headings at or above the AA floor in both themes', () => {
    const bg = token('--shell-nav-bg')
    const fg = token('--shell-nav-section-text')

    expect(contrast(fg, bg)).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
    expect(contrast(fg, V2_DARK_RAIL_BG)).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
  })

  it('keeps every other rail *text* token above the AA floor', () => {
    // Guards the tokens that pass today, so a future palette edit cannot quietly
    // demote one of them. `--shell-nav-num` is deliberately absent: ADR-0027
    // records it as a knowingly accepted 3.53:1 pending a hover-state decision,
    // and a test asserting otherwise would fail on a state the ADR sanctions.
    const bg = token('--shell-nav-bg')
    for (const name of ['--shell-nav-text', '--shell-nav-text-muted', '--shell-nav-text-dim']) {
      expect(contrast(token(name), bg), `${name} against the rail`).toBeGreaterThanOrEqual(
        AA_NORMAL_TEXT,
      )
    }
  })

  it('agrees with the measurements ADR-0027 records', () => {
    // Pins the arithmetic itself. If this drifts, the ratios quoted in the ADR
    // and in the design/v2 correction note are no longer the ones being enforced.
    expect(contrast('#6a6a60', '#0e0e0e')).toBeCloseTo(3.53, 2)
    expect(contrast('#7b7b71', '#0e0e0e')).toBeCloseTo(4.52, 2)
    expect(contrast('#7b7b71', V2_DARK_RAIL_BG)).toBeCloseTo(4.66, 2)
  })
})

describe('nav count badge contrast floor (AAASM-5171)', () => {
  // The count chip sets its text to `var(--paper-2)` over `var(--danger)`.
  // It first shipped as a literal `#fff`, which held in light (6.22:1) but, in
  // dark, sat on the lightened `--danger` (#f08a82) at 2.42:1 — below AA on
  // 9px/weight-600 text, where no large-text exemption applies. This resolves
  // both tokens through styles.css for each theme and fails if a future palette
  // edit drops the chip below the floor. Assert the ratio, not the hex.
  it('keeps the badge text above the AA floor in both themes', () => {
    const fg = referencedToken('.appshell__nav-badge', 'color')
    const bg = referencedToken('.appshell__nav-badge', 'background')
    for (const theme of THEMES) {
      expect(
        contrast(themeToken(fg, theme), themeToken(bg, theme)),
        `${fg} on ${bg} (${theme})`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
    }
  })

  it('pins the WCAG formula against the hexes measured for the badge', () => {
    // Literal hexes, not the shipped tokens: this pins the arithmetic behind the
    // AAASM-5171 review trail, so it keeps passing if the palette later moves.
    expect(contrast('#ffffff', '#f08a82')).toBeCloseTo(2.42, 2) // old #fff on dark --danger, rejected
    expect(contrast('#1c1a16', '#f08a82')).toBeCloseTo(7.17, 2) // --paper-2 on dark --danger, shipped
    expect(contrast('#ffffff', '#b8291e')).toBeCloseTo(6.22, 2) // --paper-2 on light --danger, shipped
  })
})
