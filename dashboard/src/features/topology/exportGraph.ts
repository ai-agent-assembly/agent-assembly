import type { TopologyEdge, TopologyNode } from './types'

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

/** Serialise the node/edge view model to pretty-printed JSON. */
export function buildGraphJson(
  nodes: readonly TopologyNode[],
  edges: readonly TopologyEdge[],
): string {
  return JSON.stringify({ nodes, edges }, null, 2)
}

/**
 * Serialise a rendered graph `<svg>` to a standalone SVG document string.
 *
 * Clones the node so the live DOM is untouched, stamps the SVG namespace (a
 * detached clone loses the implicit one the browser adds), and prepends an XML
 * prolog so the result opens as a standalone `.svg` file.
 */
export function serializeGraphSvg(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
  clone.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink')
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
