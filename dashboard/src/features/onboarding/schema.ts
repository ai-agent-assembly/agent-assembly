/**
 * Runtime shape for the registry answer the enroll step reports (AAASM-5380).
 *
 * ## Why this exists
 *
 * `useRegisteredAgentsQuery` threw on an absent body and then read `data.total`
 * and `data.items` off a cast `PaginatedAgentResponse` — a cast, not a check. A
 * `200` whose body had no `total` rendered an empty meter and the pane printed
 * "the registry answered: no agents registered yet", an affirmative all-clear
 * about the fleet derived from a body nobody parsed; a truthy non-array `items`
 * survived the cast and threw in `.map` at render. Same class of untruth
 * `features/approvals/schema.ts` removed from the Live-Ops surfaces, on the step
 * that tells an operator their first agent is (or is not) governed.
 *
 * ## Why these fields and no more
 *
 * An absence must be no wider than the evidence for it — the rule
 * `features/policies/schema.ts`, `features/capability/schema.ts` and
 * `features/approvals/schema.ts` all follow. The step reads exactly:
 *
 *  - `total`, the registry's own count, which drives the meter and the badge;
 *  - `items.length` for the "no agents registered yet" line, and per listed row
 *    `id` (React key), `name`, and `framework` (both rendered as text). It also
 *    renders `last_event`, but through `certain(..., 'unknown')`, which is
 *    already total on an absent value — so a missing `last_event` is not a fault
 *    and is deliberately not required here.
 *
 * So the envelope schema requires `total` as a number and `items` as an array of
 * rows carrying `id`, `name` and `framework` as strings. Everything else
 * `PaginatedAgentResponse` and `AgentResponse` carry (`page`, `per_page`,
 * `status`, `is_flagged`, the session/trace arrays) the step never reads, so
 * validating it would blank a determinable count because a field the step never
 * looks at was malformed.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'
import type { RegisteredAgents } from './api'

type PaginatedAgentResponse = components['schemas']['PaginatedAgentResponse']
type AgentResponse = components['schemas']['AgentResponse']

/**
 * The fields the enroll step reads off one listed registry row.
 *
 * Typed from the generated response rather than written out, so renaming any of
 * these in `openapi/v1.yaml` fails this module's build — indexing a key the
 * generated type no longer has is an error.
 */
export interface RegisteredAgentRow {
  readonly id: AgentResponse['id']
  readonly name: AgentResponse['name']
  readonly framework: AgentResponse['framework']
}

/** The envelope fields the step reads: the count, and the page of rows. */
export interface RegistryAnswer {
  readonly total: PaginatedAgentResponse['total']
  readonly items: readonly RegisteredAgentRow[]
}

/**
 * A conforming registry row still carries `id`, `name` and `framework` under
 * those names, required, as strings; a conforming envelope still carries a
 * numeric `total` and an array `items`.
 *
 * The `satisfies` below bind the schemas to these interfaces; these bind the
 * interfaces to the generated response, in the direction the indexed access
 * cannot. If `openapi/v1.yaml` makes any of them optional or retypes it, this
 * resolves to `never` and the assignment stops compiling. Mirrors
 * `features/approvals/schema.ts`'s `APPROVAL_ROW_IS_ON_THE_WIRE`.
 */
type GeneratedCarriesRegistryAnswer = PaginatedAgentResponse extends {
  total: number
  items: readonly RegisteredAgentRow[]
}
  ? true
  : never
export const REGISTRY_ANSWER_IS_ON_THE_WIRE: GeneratedCarriesRegistryAnswer = true

const registryRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  framework: z.string(),
}) satisfies z.ZodType<RegisteredAgentRow>

const registryAnswerSchema = z.object({
  total: z.number(),
  items: z.array(registryRowSchema),
}) satisfies z.ZodType<RegistryAnswer>

/** The first thing wrong with the body, as a short operator-facing phrase. */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Decode the registry answer down to the count and rows the step reads, or say
 * why it could not be read.
 *
 * The result is assignable to `RegisteredAgents` — the rows are a subtype of
 * `RegisteredAgent` carrying the three fields the step renders — so the fold
 * feeds it straight to the existing meter and list.
 *
 * Total, per the {@link Decoder} contract — a decoder that threw would re-create
 * the render-time `.map` crash it exists to prevent, one stack frame further in.
 */
export const decodeRegistryAnswer: Decoder<RegisteredAgents> = (body: unknown) => {
  const parsed = registryAnswerSchema.safeParse(body)
  // Return the original body, not `parsed.data`: the count and the three fields
  // per row the step renders are proven, and the rest of each `AgentResponse`
  // (`last_event`, which the step reads through `certain(...)`) survives
  // untouched. The cast is sound because `parsed.success` established `total` is
  // a number and every row carries `id`/`name`/`framework`.
  if (parsed.success) return conforms(body as RegisteredAgents)
  return violates(
    `The agent registry came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so how many agents are registered cannot be stated — including whether none are yet. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}
