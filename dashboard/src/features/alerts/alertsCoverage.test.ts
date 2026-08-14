import { describe, expect, it } from 'vitest'
import { alertsCountLabel } from './alertsCoverage'

// `coversWholeFleet` / `statsScopeNote` are covered in AlertStatsStrip.test.tsx,
// which renders them; this file covers the count label, whose whole job is to
// keep its two numbers in the same population.
describe('alertsCountLabel', () => {
  it('states a bare count when nothing is narrowed and the page is the fleet', () => {
    expect(alertsCountLabel(3, 3, true)).toBe('3 alerts')
  })

  it('singularises one alert', () => {
    expect(alertsCountLabel(1, 1, true)).toBe('1 alert')
  })

  it('names shown and loaded together when narrowed — both page figures', () => {
    expect(alertsCountLabel(1, 3, true)).toBe('1 of 3 alerts')
  })

  it('qualifies the scope when the page is not the whole fleet', () => {
    expect(alertsCountLabel(50, 50, false)).toBe('50 alerts on this page')
  })

  it('qualifies a narrowed count too, and never names the fleet total', () => {
    expect(alertsCountLabel(7, 50, false)).toBe('7 of 50 alerts on this page')
  })

  it('reports a real zero without dressing it up', () => {
    expect(alertsCountLabel(0, 0, true)).toBe('0 alerts')
    expect(alertsCountLabel(0, 12, true)).toBe('0 of 12 alerts')
  })
})
