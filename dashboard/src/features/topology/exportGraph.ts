import type { TopologyEdge, TopologyNode } from './types'
import { isUnclaimedTeam } from './unclaimed'

/**
 * Client-side graph export for the topology view (AAASM-5071).
 *
 * Two formats, both produced entirely in the browser — no server round-trip:
 * - **JSON** — the raw node/edge view model, for programmatic reuse.
 * - **SVG** — a self-contained snapshot of the rendered graph, for embedding
 *   in docs/tickets.
 *
 * The string builders are pure so they unit-test without a DOM; only
 * {@link triggerDownload} touches browser APIs.
 */

/**
 * Serialise the node/edge view model to pretty-printed JSON.
 *
 * The unclaimed group's key is a rendering device, not a team the registry
 * holds, so it is unwound back to `team: null` — the wire's own answer for an
 * agent no team claims (AAASM-5184). Exporting the `__orphan__` sentinel would
 * hand a downstream consumer a team id that no API ever asserted, which is the
 * same fabrication the sentinel exists to stop the *screen* making.
 */
export function buildGraphJson(
  nodes: readonly TopologyNode[],
  edges: readonly TopologyEdge[],
): string {
  const exported = nodes.map((n) => (isUnclaimedTeam(n.team) ? { ...n, team: null } : n))
  return JSON.stringify({ nodes: exported, edges }, null, 2)
}

/**
 * Serialise a rendered graph `<svg>` to a standalone SVG document string.
 *
 * Clones the node so the live DOM is untouched, stamps the SVG namespace (a
 * detached clone loses the implicit one the browser adds), and prepends an XML
 * prolog so the result opens as a standalone `.svg` file.
 *
 * The unclaimed cluster's `data-team` is dropped from the clone for the same
 * reason {@link buildGraphJson} unwinds the sentinel to `null` (AAASM-5184):
 * this is a file that leaves the app, and `data-team="__orphan__"` would assert
 * a team id no API ever returned. Removing the attribute — rather than blanking
 * it — is the honest encoding, because `data-unclaimed="true"` on the same
 * element already carries the fact, and an empty `data-team` is exactly the
 * blank-team claim the ticket exists to stop making.
 */
export function serializeGraphSvg(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
  clone.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink')
  for (const el of clone.querySelectorAll<SVGElement>('[data-unclaimed="true"][data-team]')) {
    delete el.dataset.team
  }
  const body = new XMLSerializer().serializeToString(clone)
  return `<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n${body}`
}

/**
 * Download `content` as a file named `filename`. Uses an object URL + a
 * transient anchor click, revoking the URL afterwards so it is not leaked.
 */
export function triggerDownload(filename: string, mimeType: string, content: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

/** Export the graph view model as `topology-graph.json`. */
export function exportGraphJson(
  nodes: readonly TopologyNode[],
  edges: readonly TopologyEdge[],
): void {
  triggerDownload('topology-graph.json', 'application/json', buildGraphJson(nodes, edges))
}

/** Export a rendered graph `<svg>` snapshot as `topology-graph.svg`. */
export function exportGraphSvg(svg: SVGSVGElement): void {
  triggerDownload('topology-graph.svg', 'image/svg+xml', serializeGraphSvg(svg))
}
