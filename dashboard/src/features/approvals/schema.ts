/**
 * Runtime shape for the pending-approvals rows the Live-Ops surfaces and the
 * Overview approvals card read (AAASM-5380).
 *
 * ## Why this exists
 *
 * `useApprovalsQuery` used to return `data?.items ?? []` and the folds cast that
 * to `Approval[]`. A body with no `items` therefore reached the header bell and
 * the Live-Ops pool as a *known empty queue*: the bell's aria-label read "no
 * approvals are waiting" and the pool rendered "No pending approvals / Nothing
 * is waiting for a human decision right now" — an affirmative all-clear derived
 * from a body nobody could parse. A truthy non-array `items` was worse still: it
 * survived the cast and threw in `.map` at render. This is the same class of
 * untruth AAASM-5369 removed from the policy badge, on the surface an operator
 * watches to decide whether a human is being asked to act.
 *
 * ## Why these fields and no more
 *
 * An absence must be no wider than the evidence for it — the rule
 * `features/policies/schema.ts` and `features/capability/schema.ts` both follow.
 * The three surfaces that fold through this decoder read exactly:
 *
 *  - the bell: `items.length` and nothing off any row;
 *  - the pool: per row `id` (React key, `data-approval-id`, and the id the
 *    decide endpoints parse with `Uuid::parse_str`), `agent_id`, `action`, and
 *    `expires_at` (truthiness-guarded before the countdown);
 *  - the Overview approvals card (AAASM-5380 slice S8): `items.length` for the
 *    count, and `created_at` per row for the derived "{n} urgent · oldest {age}"
 *    headline (`deriveApprovalsSummary`, `features/approvals/summary.ts`).
 *
 * So the row schema requires `id`, `agent_id`, `action` and `status` as strings
 * — the fields these surfaces put on screen or key off — plus `expires_at` (the
 * pool's countdown) and `created_at` (the Overview urgency headline) as strings.
 * Everything else the generated `ApprovalResponse` carries (`reason`, `quorum`,
 * `routing_status`, `team_id`) is not read by any of them and is deliberately
 * not validated: a malformed `quorum` must not blank a queue whose ids and
 * actions are perfectly renderable.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'

type ApprovalResponse = components['schemas']['ApprovalResponse']

/**
 * The fields the bell and the pool are entitled to read off a row.
 *
 * Typed from the generated response rather than written out, so renaming any of
 * these in `openapi/v1.yaml` fails this module's build — indexing a key the
 * generated type no longer has is an error.
 */
export interface ApprovalRow {
  readonly id: ApprovalResponse['id']
  readonly agent_id: ApprovalResponse['agent_id']
  readonly action: ApprovalResponse['action']
  readonly status: ApprovalResponse['status']
  readonly expires_at: ApprovalResponse['expires_at']
  readonly created_at: ApprovalResponse['created_at']
}

/**
 * A conforming approval row still carries these five fields, required, as
 * strings.
 *
 * The `satisfies` below binds the schema to {@link ApprovalRow}; this binds
 * {@link ApprovalRow} to the generated response, in the direction the indexed
 * access cannot. If `openapi/v1.yaml` makes any of them optional or retypes it,
 * this resolves to `never` and the assignment stops compiling. Mirrors
 * `features/policies/schema.ts`'s `POLICY_ACTIVITY_IS_ON_THE_WIRE`.
 */
type GeneratedCarriesApprovalRow = ApprovalResponse extends ApprovalRow ? true : never
export const APPROVAL_ROW_IS_ON_THE_WIRE: GeneratedCarriesApprovalRow = true

const approvalRowSchema = z.object({
  id: z.string(),
  agent_id: z.string(),
  action: z.string(),
  status: z.string(),
  expires_at: z.string(),
  created_at: z.string(),
}) satisfies z.ZodType<ApprovalRow>

const approvalListSchema = z.array(approvalRowSchema)

/** The first thing wrong with the body, as a short operator-facing phrase. */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Decode the pending-approvals list, or say why it could not be read.
 *
 * Total, per the {@link Decoder} contract — a decoder that threw would re-create
 * the render-time `.map` crash it exists to prevent, one stack frame further in.
 */
export const decodeApprovalList: Decoder<readonly ApprovalRow[]> = (body: unknown) => {
  const parsed = approvalListSchema.safeParse(body)
  if (parsed.success) return conforms(parsed.data)
  return violates(
    `The approvals queue came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so whether anything is waiting for a human decision cannot be stated — including whether the queue is empty. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}
