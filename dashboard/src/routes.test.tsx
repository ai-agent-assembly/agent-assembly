import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect } from 'vitest'
import { CANONICAL_ROUTES, ROUTE_GROUPS } from './routes'
import { ComingSoon } from './pages/ComingSoon'

describe('CANONICAL_ROUTES config', () => {
  it('declares exactly 12 routes', () => {
    expect(CANONICAL_ROUTES).toHaveLength(12)
  })

  it('covers all three groups (monitor, control, manage)', () => {
    const groups = new Set(CANONICAL_ROUTES.map((r) => r.group))
    expect([...groups].sort()).toEqual(['control', 'manage', 'monitor'])
    for (const group of ROUTE_GROUPS) {
      expect(CANONICAL_ROUTES.filter((r) => r.group === group).length).toBeGreaterThan(0)
    }
  })

  it('has unique id, num, and path for every entry', () => {
    const ids = CANONICAL_ROUTES.map((r) => r.id)
    const nums = CANONICAL_ROUTES.map((r) => r.num)
    const paths = CANONICAL_ROUTES.map((r) => r.path)
    expect(new Set(ids).size).toBe(ids.length)
    expect(new Set(nums).size).toBe(nums.length)
    expect(new Set(paths).size).toBe(paths.length)
  })

  it('includes the 12 canonical ids from design/v1/hi-fi/shell.jsx', () => {
    const ids = CANONICAL_ROUTES.map((r) => r.id).sort()
    expect(ids).toEqual(
      [
        'alerts', 'audit', 'capability', 'costs', 'fleet', 'identity',
        'live', 'overview', 'policy', 'scrub', 'teams', 'topology',
      ].sort(),
    )
  })

  it('every num is a zero-padded two-digit sequence 01..12', () => {
    const nums = CANONICAL_ROUTES.map((r) => r.num).sort()
    expect(nums).toEqual([
      '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12',
    ])
  })
})

describe('ComingSoon', () => {
  it('renders the provided name as the heading', () => {
    render(
      <MemoryRouter>
        <ComingSoon name="Topology" />
      </MemoryRouter>,
    )
    expect(screen.getByRole('heading', { name: 'Topology' })).toBeInTheDocument()
    expect(screen.getByTestId('coming-soon')).toBeInTheDocument()
  })

  it('falls back to the pathname when no name prop is given', () => {
    render(
      <MemoryRouter initialEntries={['/scrub']}>
        <ComingSoon />
      </MemoryRouter>,
    )
    // Heading is capitalised via CSS, but DOM text is the raw pathname stripped.
    expect(screen.getByTestId('coming-soon').textContent).toContain('scrub')
  })
})
