import type { TopologyEdgeKind } from './types'

/**
 * Display metadata for the six relation kinds the topology design models
 * (`design/v1/hi-fi/topology.jsx` `TOPO_EC`): delegates_to, calls, reads,
 * writes, approves, messages.
 *
 * The live `GET /api/v1/topology` projection currently only emits the two
 * structural kinds — `delegation` and `call` — so only those two are
 * `available`. The other four are rendered in the sidebar legend/checkboxes as
 * disabled "coming soon" rows: the FE styling (colour, dash, arrowhead) is
 * ready so they light up the moment the backend widens the projection, without
 * fabricating edges that don't exist in the data (see AAASM-5071 scope note).
 *
 * `color` is a CSS value (token where one exists) so swatches and edges
 * re-theme in light/dark — the design's raw hex would not. `approves` has no
 * matching token, so it keeps the design's violet hex.
 */
export interface EdgeKindMeta {
  /** Design vocabulary id, also used as the checkbox key and CSS class suffix. */
  readonly id: string
  /** Human-readable label shown in the sidebar and legend. */
  readonly label: string
  /** Whether the `/topology` projection currently emits this kind. */
  readonly available: boolean
  /** The {@link TopologyEdgeKind} this maps onto, when {@link available}. */
  readonly modelKind?: TopologyEdgeKind
  /** Stroke/legend colour (CSS value; token where one exists). */
  readonly color: string
  /** Dash pattern for the stroke, or undefined for a solid line. */
  readonly dash?: string
  /** Stroke width in px. */
  readonly width: number
}

export const EDGE_KINDS: readonly EdgeKindMeta[] = [
  { id: 'delegates_to', label: 'delegates_to', available: true, modelKind: 'delegation', color: 'var(--ink-3)', width: 2 },
  { id: 'calls', label: 'calls', available: true, modelKind: 'call', color: 'var(--info)', dash: '7 3', width: 1.5 },
  { id: 'reads', label: 'reads', available: false, color: 'var(--ok)', dash: '3 4', width: 1.5 },
  { id: 'writes', label: 'writes', available: false, color: 'var(--warn)', dash: '3 4', width: 1.5 },
  { id: 'approves', label: 'approves', available: false, color: '#7c3aed', dash: '8 3', width: 1.5 },
  { id: 'messages', label: 'messages', available: false, color: 'var(--ink-4)', dash: '2 5', width: 1 },
]

/** The model kinds the graph can actually render, in a stable set. */
export const AVAILABLE_EDGE_KINDS: readonly TopologyEdgeKind[] = EDGE_KINDS.filter(
  (k): k is EdgeKindMeta & { modelKind: TopologyEdgeKind } => k.available && k.modelKind != null,
).map((k) => k.modelKind)

/** Fresh mutable set of the available model kinds — the default "all visible" filter. */
export function defaultVisibleKinds(): Set<TopologyEdgeKind> {
  return new Set(AVAILABLE_EDGE_KINDS)
}
