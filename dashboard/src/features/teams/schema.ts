/**
 * Runtime shapes for the two answers the Cost & Budget and Teams pages fold into
 * the truthfulness vocabulary (AAASM-5380 slice S7): the cost summary and the
 * topology overview.
 *
 * ## Why this exists
 *
 * `useCostSummaryQuery` and `useTopologyOverviewQuery` (`features/teams/api.ts`)
 * both end in a bare `data as …` cast — the module comment there calls them
 * accepted-risk. So `QueryOutcome<CostSummary>` / `QueryOutcome<TopologyOverview>`
 * carry a claim the wire has not earned, and every downstream read is
 * optional-chained so nothing throws. That is *worse* than the unmount
 * AAASM-5366 fixed, because it is silent:
 *
 *  - **CostsPage.** A non-null malformed cost body means `whenEmpty:
 *    "unconfigured"` never fires (the body is present), and `countBlockedByBudget`
 *    walks a `per_team` that a proxy rewrote as if it were rows, reporting a
 *    measured-looking `known(0)` teams blocked by budget — a fabricated clean
 *    bill of health on the one KPI that exists to deny it, the same class of
 *    untruth AAASM-5185 removed.
 *  - **TeamsPage.** A `200` missing `total_agent_count` makes
 *    `reconcileAgentCensus` compute `total_agent_count - grouped` as
 *    `undefined - N === NaN`; `NaN === 0` is false, so `CensusNotice` renders a
 *    disagreement worded with `NaN` rather than reporting that the registry tally
 *    could not be read at all.
 *
 * ## Why these fields and no more
 *
 * An absence must be no wider than the evidence for it — the rule every migrated
 * schema in this tree follows.
 *
 *  - **The cost summary.** `deriveCostKpis` and `joinTeamRows` read
 *    `daily_spend_usd` and `date` unconditionally, `daily_limit_usd` /
 *    `monthly_spend_usd` / `monthly_limit_usd` through `parseUsd` (which tolerates
 *    absence), and `per_agent` / `per_team` for their length and — for
 *    `per_team` — each row's `team_id` and `daily_spend_usd`. So the schema
 *    requires the two fields always read as-is (`daily_spend_usd`, `date`),
 *    accepts the optional USD strings when present, and checks the two breakdown
 *    arrays are arrays whose rows carry the fields the join keys and sums by. It
 *    deliberately does **not** require `daily_limit_usd`: its absence is the
 *    `unconfigured` signal the page already reads honestly, so requiring it would
 *    blank a usable summary over the very field whose absence is meaningful.
 *  - **The topology overview.** Both pages read `teams` (`joinTeamRows` and the
 *    census sum), and TeamsPage additionally reads `total_agent_count` — the one
 *    field whose absence produces the census `NaN`. So the schema requires
 *    `total_agent_count` as a number and `teams` as an array whose rows carry the
 *    `team_id` and `agent_count` the two consumers read. One decoder validating
 *    the superset both pages read, rather than two, because the fields do not
 *    conflict and a single absence rendering is simpler to reason about.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'
import type { CostSummary, TopologyOverview } from './api'

type WireCostSummary = components['schemas']['CostSummary']
type WireTeamCostEntry = components['schemas']['TeamCostEntry']
type WireTopologyOverview = components['schemas']['TopologyOverview']
type WireTeamSummary = components['schemas']['TeamSummary']

/** The first thing wrong with the body, as a short operator-facing phrase. */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * The fields the Cost & Budget page reads off the summary and its per-team rows.
 *
 * Typed from the generated response rather than written out, so renaming any of
 * these in `openapi/v1.yaml` fails this module's build. `daily_limit_usd`,
 * `monthly_spend_usd` and `monthly_limit_usd` are optional and nullable exactly
 * as they are on the wire — their absence is the `unconfigured` signal the page
 * reads, not a fault.
 */
export interface CostSummaryFields {
  readonly daily_spend_usd: WireCostSummary['daily_spend_usd']
  readonly date: WireCostSummary['date']
  readonly daily_limit_usd?: Exclude<WireCostSummary['daily_limit_usd'], undefined>
  readonly monthly_spend_usd?: Exclude<WireCostSummary['monthly_spend_usd'], undefined>
  readonly monthly_limit_usd?: Exclude<WireCostSummary['monthly_limit_usd'], undefined>
  readonly per_agent?: readonly unknown[]
  readonly per_team?: readonly {
    readonly team_id: WireTeamCostEntry['team_id']
    readonly daily_spend_usd: WireTeamCostEntry['daily_spend_usd']
  }[]
}

/**
 * A conforming summary still carries these fields under these names.
 *
 * The `satisfies` below binds the schema to {@link CostSummaryFields}; this binds
 * {@link CostSummaryFields} to the generated response. If `openapi/v1.yaml`
 * retypes any of them this resolves to `never` and the assignment stops
 * compiling. Mirrors `features/agents/schema.ts`'s `FLEET_AGENT_ROW_IS_ON_THE_WIRE`.
 */
type GeneratedCarriesCostSummaryFields = WireCostSummary extends CostSummaryFields ? true : never
export const COST_SUMMARY_FIELDS_ARE_ON_THE_WIRE: GeneratedCarriesCostSummaryFields = true

const costSummarySchema = z.object({
  daily_spend_usd: z.string(),
  date: z.string(),
  daily_limit_usd: z.string().nullish(),
  monthly_spend_usd: z.string().nullish(),
  monthly_limit_usd: z.string().nullish(),
  per_agent: z.array(z.unknown()).optional(),
  // `team_id` and `daily_spend_usd` are the two fields `joinTeamRows` keys and
  // sums each row by; a row missing either is what silently produced the
  // fabricated `known(0)` blocked-by-budget count. Other row fields stay
  // unchecked — `monthly_spend_usd` is read through `parseUsd`, which tolerates
  // absence.
  per_team: z
    .array(z.object({ team_id: z.string(), daily_spend_usd: z.string() }).passthrough())
    .optional(),
}) satisfies z.ZodType<CostSummaryFields>

/**
 * Decode the cost summary down to what the page reads, or say why it could not
 * be read.
 *
 * The result is assignable to `CostSummary` — the required fields are proven
 * present and typed, and the rest the page reads through optional access
 * survives untouched. Total, per the {@link Decoder} contract.
 */
export const decodeCostSummary: Decoder<CostSummary> = (body: unknown) => {
  const parsed = costSummarySchema.safeParse(body)
  // Return the original body, not `parsed.data`: the required fields are proven,
  // and the rest of the `CostSummary` (read through `parseUsd` / optional access)
  // survives untouched. The cast is sound because `parsed.success` established
  // the summary carries what the KPI strip and the per-team join read.
  if (parsed.success) return conforms(body as CostSummary)
  return violates(
    `The cost summary came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so nothing about spend or budget can be stated — including whether any budget is configured. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}

/**
 * The fields the Cost & Budget page and the Teams page read off the overview.
 *
 * `total_agent_count` is the one whose absence makes the Teams census go `NaN`;
 * `teams` is read by both pages (`joinTeamRows` and the census sum). Typed from
 * the generated response so a rename in `openapi/v1.yaml` fails this build.
 */
export interface TopologyOverviewFields {
  readonly total_agent_count: WireTopologyOverview['total_agent_count']
  readonly teams: readonly {
    readonly team_id: WireTeamSummary['team_id']
    readonly agent_count: WireTeamSummary['agent_count']
  }[]
}

/** A conforming overview still carries these fields under these names. */
type GeneratedCarriesTopologyOverviewFields =
  WireTopologyOverview extends TopologyOverviewFields ? true : never
export const TOPOLOGY_OVERVIEW_FIELDS_ARE_ON_THE_WIRE: GeneratedCarriesTopologyOverviewFields = true

const topologyOverviewSchema = z.object({
  // A number, required — this is the whole TeamsPage defect: a missing
  // `total_agent_count` made `total_agent_count - grouped` compute to `NaN`
  // rather than reporting the tally could not be read.
  total_agent_count: z.number(),
  // `team_id` and `agent_count` are what `joinTeamRows` maps by and the census
  // sums; other team fields stay unchecked.
  teams: z.array(z.object({ team_id: z.string(), agent_count: z.number() }).passthrough()),
}) satisfies z.ZodType<TopologyOverviewFields>

/**
 * Decode the topology overview down to what the two pages read, or say why it
 * could not be read.
 *
 * The result is assignable to `TopologyOverview` — the required fields are
 * proven, and the rest survives untouched. Total, per the {@link Decoder}
 * contract.
 */
export const decodeTopologyOverview: Decoder<TopologyOverview> = (body: unknown) => {
  const parsed = topologyOverviewSchema.safeParse(body)
  // Return the original body, not `parsed.data`: `total_agent_count` and the two
  // per-team fields are proven, and the rest of the `TopologyOverview` survives
  // untouched. The cast is sound because `parsed.success` established the
  // overview carries what the roster join and the census read.
  if (parsed.success) return conforms(body as TopologyOverview)
  return violates(
    `The topology overview came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so how many agents the registry reports and which teams exist cannot be stated. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}
