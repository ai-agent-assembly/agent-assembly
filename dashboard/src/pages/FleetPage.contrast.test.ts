// Contrast floor for the Fleet no-rows states (AAASM-5130 / ADR-0027).
//
// The AAASM-5130 callout and the header count are the two places Fleet now
// *explains itself* — "no agents match these filters", and the `NO_DATA`
// em-dash that replaces a fleet size the request never established. Both first
// rendered in `--ink-4`, which measures 3.45:1 (light) / 3.83:1 (dark): below
// the WCAG 2.1 AA floor, with no large-text exemption available at 12–14px /
// weight 400. ADR-0027 records that the accessibility floor overrides the
// visual specification, so this test is the enforcement.
//
// It follows the AppShell.contrast.test.ts pattern deliberately rather than
// inventing a second one — same luminance maths, same "assert the ratio, not
// the hex" rule, same reason for living in the unit suite: no CI job runs the
// dashboard Playwright suite, so a check placed in an e2e spec would never
// execute.
//
// The one structural difference is that Fleet's rules only *reference* tokens —
// the values live in the global stylesheet — so this resolves each rule's
// `color:` through `styles.css` for both themes. That means it fails if a later
// edit changes the rule, the token, or either theme's palette.
import { describe, expect, it } from 'vitest'
// `?raw` rather than a normal import: the assertion is about the literal values
// the stylesheets ship, which a bundled CSS import would not expose.
import FLEET_CSS from './FleetPage.css?raw'
import GLOBAL_CSS from '../styles.css?raw'

type Theme = 'light' | 'dark'

/** The declaration block of a top-level rule, by exact selector. */
function ruleBody(css: string, selector: string): string {
  const start = css.indexOf(`\n${selector} {`)
  if (start === -1) throw new Error(`rule ${selector} not found`)
  const end = css.indexOf('\n}', start)
  return css.slice(start, end)
}

/** The custom property a rule points `property` at, e.g. `color: var(--ink-3)`. */
function referencedToken(selector: string, property: string): string {
  const match = new RegExp(`${property}:\\s*var\\((--[a-z0-9-]+)\\)`).exec(
    ruleBody(FLEET_CSS, selector),
  )
  if (!match?.[1]) throw new Error(`${selector} has no ${property}: var(--…)`)
  return match[1]
}

/** Resolve a token to the hex the given theme ships. */
function themeToken(name: string, theme: Theme): string {
  const body = ruleBody(GLOBAL_CSS, theme === 'light' ? ':root' : ':root[data-theme="dark"]')
  const match = new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`).exec(body)
  if (!match?.[1]) throw new Error(`token ${name} not found in the ${theme} palette`)
  return match[1].toLowerCase()
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

/**
 * WCAG 2.1 AA, normal text.
 *
 * Both rules guarded here render at 12px and 14px, weight 400 — the 3:1
 * large-text exemption needs ≥18.66px, or ≥14px at weight 700.
 */
const AA_NORMAL_TEXT = 4.5

const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * Both grounds either rule can land on.
 *
 * `--paper-2` is what actually ships beneath them today (`.fleet-page__head`
 * and `.fleet-table__wrap` both set it), but `.fleet-page` itself is `--paper`,
 * and light `--paper` is the *darker* of the two — so asserting against both
 * means a later layout change that drops one of these onto the page ground
 * cannot silently fall below the floor.
 */
const GROUNDS = ['--paper', '--paper-2'] as const

describe('Fleet no-rows contrast floor (ADR-0027)', () => {
  it('renders the filtered-empty headline at or above the AA floor in both themes', () => {
    const fg = referencedToken('.fleet-empty__title', 'color')
    for (const theme of THEMES) {
      for (const ground of GROUNDS) {
        expect(
          contrast(themeToken(fg, theme), themeToken(ground, theme)),
          `${fg} on ${ground} (${theme})`,
        ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
      }
    }
  })

  it('renders the header count — including the NO_DATA em-dash — above the AA floor', () => {
    // This span asserts the fleet size, or explicitly declines to. An operator
    // who cannot read the `—` reads the absence as a blank, which is precisely
    // the "silence where a governance value belongs" the truthfulness
    // vocabulary exists to prevent.
    const fg = referencedToken('.fleet-page__count', 'color')
    for (const theme of THEMES) {
      for (const ground of GROUNDS) {
        expect(
          contrast(themeToken(fg, theme), themeToken(ground, theme)),
          `${fg} on ${ground} (${theme})`,
        ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
      }
    }
  })

  it('keeps the callout body and its clear-filters button above the floor', () => {
    // These two passed on first render and are pinned so a later "tidy the
    // greys" pass cannot demote them to the value the two rules above had.
    for (const theme of THEMES) {
      expect(
        contrast(themeToken('--ink-3', theme), themeToken('--paper-2', theme)),
        `--ink-3 body copy (${theme})`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
      expect(
        contrast(themeToken('--ink', theme), themeToken('--paper-2', theme)),
        `--ink button label (${theme})`,
      ).toBeGreaterThanOrEqual(AA_NORMAL_TEXT)
    }
  })

  it('agrees with the measurements recorded in the AAASM-5130 review', () => {
    // Pins the arithmetic itself against the values measured in Chromium via
    // getComputedStyle on the built app. If this drifts, the ratios quoted in
    // the review trail are no longer the ones being enforced.
    expect(contrast('#8a8a8a', '#ffffff')).toBeCloseTo(3.45, 2) // --ink-4 light, rejected
    expect(contrast('#7a766c', '#1c1a16')).toBeCloseTo(3.83, 2) // --ink-4 dark, rejected
    expect(contrast('#5a5a5a', '#ffffff')).toBeCloseTo(6.9, 2) // --ink-3 light, shipped
    expect(contrast('#aaa599', '#1c1a16')).toBeCloseTo(7.07, 2) // --ink-3 dark, shipped
  })
})
