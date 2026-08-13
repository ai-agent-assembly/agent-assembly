import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  buildGraphJson,
  exportGraphJson,
  serializeGraphSvg,
  triggerDownload,
} from './exportGraph'
import type { TopologyEdge, TopologyNode } from './types'
import { UNCLAIMED_TEAM } from './unclaimed'

const NODES: TopologyNode[] = [
  { id: 'a', name: 'a', status: 'active', team: 't', owner: 'o', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
]
const EDGES: TopologyEdge[] = [{ source: 'a', target: 'a', kind: 'delegation' }]

describe('buildGraphJson', () => {
  it('serialises nodes + edges as pretty-printed JSON that round-trips', () => {
    const json = buildGraphJson(NODES, EDGES)
    expect(json).toContain('\n  ') // pretty-printed (2-space indent)
    expect(JSON.parse(json)).toEqual({ nodes: NODES, edges: EDGES })
  })

  it('exports an unclaimed agent as team: null, not as the sentinel key', () => {
    // The sentinel is a rendering device. Writing `"team": "__orphan__"` into
    // an export would hand a downstream consumer a team id no API asserted
    // (AAASM-5184).
    const unclaimed: TopologyNode[] = [{ ...NODES[0], team: UNCLAIMED_TEAM }]
    const parsed = JSON.parse(buildGraphJson(unclaimed, EDGES)) as { nodes: { team: unknown }[] }
    expect(parsed.nodes[0].team).toBeNull()
  })

  it('leaves a real team id in the export untouched', () => {
    const parsed = JSON.parse(buildGraphJson(NODES, EDGES)) as { nodes: { team: unknown }[] }
    expect(parsed.nodes[0].team).toBe('t')
  })
})

describe('serializeGraphSvg', () => {
  it('stamps the SVG namespace + XML prolog on a detached clone', () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect')
    svg.appendChild(rect)
    const out = serializeGraphSvg(svg)
    expect(out.startsWith('<?xml')).toBe(true)
    expect(out).toContain('xmlns="http://www.w3.org/2000/svg"')
    expect(out).toContain('<rect')
  })

  it('does not write the unclaimed sentinel into the exported file', () => {
    // The SVG leaves the app just like the JSON does, so it must not assert a
    // team id no API returned either (AAASM-5184). `data-unclaimed` already
    // says what the group is.
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    const cluster = document.createElementNS('http://www.w3.org/2000/svg', 'g')
    cluster.setAttribute('data-team', UNCLAIMED_TEAM)
    cluster.setAttribute('data-unclaimed', 'true')
    svg.appendChild(cluster)

    const out = serializeGraphSvg(svg)

    expect(out).not.toContain(UNCLAIMED_TEAM)
    expect(out).not.toContain('data-team')
    expect(out).toContain('data-unclaimed="true"')
  })

  it('leaves a real team cluster’s data-team intact', () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    const cluster = document.createElementNS('http://www.w3.org/2000/svg', 'g')
    cluster.setAttribute('data-team', 'support')
    svg.appendChild(cluster)
    expect(serializeGraphSvg(svg)).toContain('data-team="support"')
  })

  it('leaves the live DOM untouched', () => {
    // The clone is what gets stripped — exporting must not mutate the canvas
    // the operator is still looking at.
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    const cluster = document.createElementNS('http://www.w3.org/2000/svg', 'g')
    cluster.setAttribute('data-team', UNCLAIMED_TEAM)
    cluster.setAttribute('data-unclaimed', 'true')
    svg.appendChild(cluster)

    serializeGraphSvg(svg)

    expect(cluster.getAttribute('data-team')).toBe(UNCLAIMED_TEAM)
  })
})

describe('triggerDownload', () => {
  afterEach(() => vi.restoreAllMocks())

  it('creates an object URL, clicks a transient anchor, then revokes the URL', () => {
    const createUrl = vi.fn(() => 'blob:mock')
    const revokeUrl = vi.fn()
    // jsdom does not implement the object-URL API — stub it for this test.
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    triggerDownload('graph.json', 'application/json', '{}')

    expect(createUrl).toHaveBeenCalledTimes(1)
    expect(click).toHaveBeenCalledTimes(1)
    expect(revokeUrl).toHaveBeenCalledWith('blob:mock')
    // Anchor is removed from the DOM after the click.
    expect(document.querySelector('a[download]')).toBeNull()
    vi.unstubAllGlobals()
  })

  it('exportGraphJson downloads the built JSON', () => {
    const createUrl = vi.fn(() => 'blob:mock')
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: vi.fn() })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    exportGraphJson(NODES, EDGES)
    expect(createUrl).toHaveBeenCalledTimes(1)
    vi.unstubAllGlobals()
  })
})
