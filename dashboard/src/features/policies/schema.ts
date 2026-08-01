/**
 * Runtime shape for the policy rows the nav badge counts (AAASM-5369).
 *
 * ## Why this exists
 *
 * `usePoliciesQuery` rejects a body with no `items` — but only for truthiness:
 * `if (!data?.items) throw`. `{ "items": {} }` and `{ "items": "none" }` both
 * pass that check, so the shell received a non-array wearing a `PolicyResponse[]`
 * annotation and called `.filter` on it. The `TypeError` escaped the shell's own
 * `ErrorBoundary` — which wraps `<Outlet />`, i.e. the page, not the chrome
 * around it — and unmounted the entire application.
 *
 * ## Why only `active`
 *
 * The badge counts rows where `active` is false and reads nothing else, so this
 * decoder asks for `active` and nothing else — the same rule
 * `features/scrub/schema.ts` applies to its window decoder. Requiring the rest
 * of `PolicyResponse` would blank a determinable count because some field the
 * badge never looks at was malformed, which is an absence wider than the
 * evidence for it.
 *
 * The rows are checked *individually*, not merely as an array. A row with no
 * `active` key is the second half of the same defect: `!undefined` is `true`,
 * so every unreadable row silently counted itself as an inactive policy and the
 * rail rendered a confident number derived from nothing.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'

type PolicyResponse = components['schemas']['PolicyResponse']

/**
 * The one field the badge reads off a policy row.
 *
 * Typed from the generated response rather than written out, so *renaming*
 * `active` in `openapi/v1.yaml` fails this module's build — indexing a key the
 * generated type no longer has is an error.
 *
 * Indexing alone does **not** catch a retype, which is why the guard below
 * exists. This docstring previously claimed it did (AAASM-5369 review): making
 * `active` optional produced zero errors across the whole dashboard, because
 * `PolicyResponse['active']` would widen to `boolean | undefined` and
 * `z.boolean()`'s output is still assignable to it. The decoder would have gone
 * on demanding a boolean, rejected every live policy row, and left a permanent
 * absence marker on the rail of a perfectly healthy deployment.
 */
export interface PolicyActivity {
  readonly active: PolicyResponse['active']
}

/**
 * A conforming policy row still carries `active` under that name, required, and
 * as a boolean.
 *
 * The `satisfies` below binds the decoder to {@link PolicyActivity}; this binds
 * {@link PolicyActivity} to the generated response, in the direction the
 * indexed access cannot. An optional or retyped `active` stops satisfying
 * `extends`, this resolves to `never`, and the assignment fails to compile.
 * Mirrors `features/capability/schema.ts`'s `CASCADE_FIELDS_ARE_ON_THE_WIRE`.
 */
type GeneratedCarriesPolicyActivity = PolicyResponse extends PolicyActivity ? true : never
export const POLICY_ACTIVITY_IS_ON_THE_WIRE: GeneratedCarriesPolicyActivity = true

const policyActivitySchema = z.object({
  active: z.boolean(),
}) satisfies z.ZodType<PolicyActivity>

const policyListSchema = z.array(policyActivitySchema)

/** The first thing wrong with the body, as a short operator-facing phrase. */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Decode the policy list, or say why it could not be read.
 *
 * Total, per the {@link Decoder} contract — this decoder exists because a throw
 * on this path takes the whole shell with it, so it must not be able to throw
 * itself.
 */
export const decodePolicyActivity: Decoder<readonly PolicyActivity[]> = (body: unknown) => {
  const parsed = policyListSchema.safeParse(body)
  if (parsed.success) return conforms(parsed.data)
  return violates(
    `The policy list came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so how many policy versions are inactive cannot be stated. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}
