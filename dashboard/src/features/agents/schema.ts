/**
 * Runtime shape for the agent rows the Fleet grid and the Teams orphan list read
 * (AAASM-5380).
 *
 * ## Why this exists
 *
 * Two folds cast an unread body to an agent list. `useAgentsQuery` returned
 * `data?.items ?? []`, so a `200` with no `items` reached the Fleet page as a
 * *known* empty fleet and rendered "No agents registered yet" — an affirmative
 * claim about the fleet from a body nobody parsed — while a truthy non-array
 * `items` threw in the sibling `.map`. `useTopologyAgentsQuery` passed `nodes`
 * through `?? []`, so a missing `nodes` rendered a confident "0 unclaimed" chip
 * and a non-array threw in `selectOrphanAgents`' `.filter`. Same class of untruth
 * `features/approvals/schema.ts` and `features/policies/schema.ts` removed
 * elsewhere.
 *
 * ## Why these fields and no more
 *
 * An absence must be no wider than the evidence for it — the rule every migrated
 * schema in this tree follows.
 *
 *  - **The fleet list.** `toFleetAgent` (`features/agents/fleetTypes.ts`) reads
 *    `id`, `name`, `framework`, `status` and `is_flagged` off every row
 *    unconditionally; `metadata`, `last_event`, `layer` and the rest are read
 *    through `?? null`/`?? {}` and so tolerate absence. So the fleet row schema
 *    requires exactly those five and validates nothing else — a malformed
 *    `session_count` must not blank a fleet whose ids and statuses render fine.
 *  - **The topology nodes.** The orphan filter reads only `team_id`, but the
 *    rows `selectOrphanAgents` returns are rendered by `TeamOrphanDetail`, which
 *    reads `id` (key + link), `name` (`.charAt(0)`), `status` and `flagged` off
 *    each. So the node schema requires those four and leaves `team_id` optional
 *    — it is optional on the wire (`team_id?: string | null`), and a row that
 *    omits it is a claimed agent, not a malformed one; requiring it would blank a
 *    perfectly readable orphan list because a healthy claimed row lacked a field
 *    the filter treats as absence anyway.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'
import type { Agent } from './api'
import type { AgentNode } from '../teams/api'

type AgentResponse = components['schemas']['AgentResponse']

/**
 * The fields the Fleet grid reads off a row.
 *
 * Typed from the generated response rather than written out, so renaming any of
 * these in `openapi/v1.yaml` fails this module's build — indexing a key the
 * generated type no longer has is an error.
 */
export interface FleetAgentRow {
  readonly id: AgentResponse['id']
  readonly name: AgentResponse['name']
  readonly framework: AgentResponse['framework']
  readonly status: AgentResponse['status']
  // Optional on purpose: the grid reads `is_flagged` defensively (a missing
  // flag renders as "not flagged", the honest default — absence of an
  // audit flag is not a fabricated measurement), so requiring it would fold an
  // otherwise-renderable agent list to absence, wider than the evidence.
  readonly is_flagged?: AgentResponse['is_flagged']
}

/**
 * A conforming fleet row carries the four identifying fields required under
 * those names (string / string / string / string), plus `is_flagged` as a
 * boolean when present (optional — a missing audit flag renders as "not
 * flagged", not a fault).
 *
 * The `satisfies` below binds the schema to {@link FleetAgentRow}; this binds
 * {@link FleetAgentRow} to the generated response, in the direction the indexed
 * access cannot. If `openapi/v1.yaml` makes any of them optional or retypes it,
 * this resolves to `never` and the assignment stops compiling. Mirrors
 * `features/approvals/schema.ts`'s `APPROVAL_ROW_IS_ON_THE_WIRE`.
 */
type GeneratedCarriesFleetAgentRow = AgentResponse extends FleetAgentRow ? true : never
export const FLEET_AGENT_ROW_IS_ON_THE_WIRE: GeneratedCarriesFleetAgentRow = true

const fleetAgentRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  framework: z.string(),
  status: z.string(),
  is_flagged: z.boolean().optional(),
}) satisfies z.ZodType<FleetAgentRow>

const fleetAgentListSchema = z.array(fleetAgentRowSchema)

/** The first thing wrong with the body, as a short operator-facing phrase. */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Decode the fleet list down to what the grid renders, or say why it could not
 * be read.
 *
 * The result is assignable to `Agent[]` — the rows are a subtype of
 * `AgentResponse` carrying the five fields the grid reads — so the fold feeds it
 * straight to `toFleetAgent`.
 *
 * Total, per the {@link Decoder} contract — a decoder that threw would re-create
 * the render-time `.map` crash it exists to prevent, one stack frame further in.
 */
export const decodeFleetAgents: Decoder<readonly Agent[]> = (body: unknown) => {
  const parsed = fleetAgentListSchema.safeParse(body)
  // Return the original body, not `parsed.data`: the five fields are proven
  // present and typed, and the rest of each `AgentResponse` the grid reads
  // through optional access (`metadata`, `last_event`) survives untouched. The
  // cast is sound because `parsed.success` established every row carries the
  // required five — the fields that make it an agent row.
  if (parsed.success) return conforms(body as readonly Agent[])
  return violates(
    `The agent list came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so which agents are registered cannot be stated — including whether none are. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}

/**
 * The fields the Teams orphan list reads off a topology node.
 *
 * `id`, `name`, `status` and `flagged` are what `TeamOrphanDetail` renders off
 * each orphan; `team_id` is what `selectOrphanAgents` filters on, kept optional
 * because it is optional on the wire and its absence *is* the orphan signal.
 * Typed from the generated node so a rename in `openapi/v1.yaml` fails this
 * build.
 */
export interface TopologyAgentNode {
  readonly id: AgentNode['id']
  readonly name: AgentNode['name']
  // Plain `string`, not the wire's closed `AgentNodeStatus` enum: the orphan
  // list renders `status` as opaque text, so a value the client has not caught
  // up to should still render rather than blank the list. The `extends` guard
  // below still binds this to the generated node — the enum is a subtype of
  // `string`, so a rename or removal of `status` still fails the build.
  readonly status: string
  readonly flagged: AgentNode['flagged']
  readonly team_id?: AgentNode['team_id']
}

/**
 * A conforming node still carries `id`, `name`, `status` and `flagged` required,
 * and `team_id` (when present) as a string.
 *
 * Same two-way binding as {@link FLEET_AGENT_ROW_IS_ON_THE_WIRE}. `status` is a
 * closed enum on the wire (`AgentNodeStatus`); the schema accepts any string so
 * a value the client has not caught up to still renders as opaque text rather
 * than blanking the whole list.
 */
type GeneratedCarriesTopologyAgentNode = AgentNode extends TopologyAgentNode ? true : never
export const TOPOLOGY_NODE_IS_ON_THE_WIRE: GeneratedCarriesTopologyAgentNode = true

const topologyNodeSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string(),
  flagged: z.boolean(),
  team_id: z.string().nullish(),
}) satisfies z.ZodType<TopologyAgentNode>

const topologyNodeListSchema = z.array(topologyNodeSchema)

/**
 * Decode the topology node list down to what the orphan list reads, or say why
 * it could not be read.
 *
 * The result is assignable to `AgentNode[]` — the rows are a subtype carrying
 * the fields the orphan list reads — so the fold feeds it straight to
 * `selectOrphanAgents`.
 *
 * Total, per the {@link Decoder} contract — a decoder that threw would re-create
 * the render-time `.filter` crash it exists to prevent, one stack frame further
 * in.
 */
export const decodeTopologyNodes: Decoder<readonly AgentNode[]> = (body: unknown) => {
  const parsed = topologyNodeListSchema.safeParse(body)
  // Return the original body, not `parsed.data`: the four rendered fields plus
  // the optional `team_id` the filter reads are proven, and the rest of each
  // `AgentNode` survives untouched. The cast is sound because `parsed.success`
  // established every row carries what the orphan list reads.
  if (parsed.success) return conforms(body as readonly AgentNode[])
  return violates(
    `The topology fleet came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so how many agents no team claims cannot be stated — including whether none are unclaimed. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}
