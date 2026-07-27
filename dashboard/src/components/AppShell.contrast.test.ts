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

/** Read a custom property's value out of the shipped stylesheet. */
function token(name: string): string {
  const match = new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`).exec(CSS)
  if (!match?.[1]) throw new Error(`token ${name} not found in AppShell.css`)
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
