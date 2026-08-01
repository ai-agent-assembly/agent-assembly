/**
 * Runtime shape for the part of the capability matrix the cascade fold reads
 * (AAASM-5369).
 *
 * ## Why this exists
 *
 * `api/capability.ts` returns `data as CapabilityMatrix` — a cast, not a check
 * — so `QueryOutcome<CapabilityMatrix>` carries a claim the wire has not
 * earned. `cascadeEvidenceFromQuery` then read `matrix.value.cascadeLoaded`
 * off it. Given `{}`, that is `undefined`, `!undefined` is `true`, and the fold
 * returned `known({ documentCount: 0 })` — a *measured* zero for a matrix that
 * was never read. `tallyVerdicts` folds a zero document count to
 * `unconfigured`, so the summary row then told an operator "no policy document
 * is loaded" on the strength of a body nobody could parse.
 *
 * That is worse than the unmount AAASM-5366 fixed, because it is silent and
 * plausible: an operator reading "no policy document is loaded" on a governance
 * surface acts on it. It is the same class of untruth as the fabricated
 * "0 leaks (30d)" posture AAASM-5112 removed.
 *
 * ## Why the schema is two fields and not the whole envelope
 *
 * Same reason `features/scrub/schema.ts` decodes `window_seconds` alone for
 * `scrubWindowFromQuery`: an absence must be no wider than the evidence for it.
 * The cascade fold reads `cascadeLoaded` and the *length* of `policies` and
 * nothing else, so a malformed `sampleCalls` row — or a policy row missing a
 * field the summary never looks at — must not blank a document count that is
 * perfectly determinable. `policies` is therefore checked for being an array,
 * not for the contents of its elements.
 *
 * The grid itself renders far more of this payload and is not covered here; see
 * the disposition table in `src/lib/truthfulness/__tests__/foldAudit.test.ts`.
 */
import { z } from 'zod'
import type { components } from '../../api/generated/schema'
import { conforms, violates, type Decoder } from '../../lib/truthfulness'

type CapabilityMatrixResponse = components['schemas']['CapabilityMatrix']

/**
 * The evidence the cascade fold is entitled to read.
 *
 * `cascadeLoaded`'s type is taken from the generated response rather than
 * written out, so renaming or retyping it in `openapi/v1.yaml` fails this
 * module's build the way `satisfies z.ZodType<…>` fails the scrub decoders'.
 * `policies` is deliberately widened to `unknown[]`: only its length is read.
 */
export interface CascadeFields {
  readonly cascadeLoaded: CapabilityMatrixResponse['cascadeLoaded']
  readonly policies: readonly unknown[]
}

/**
 * A conforming matrix still carries both fields under these names.
 *
 * The `satisfies` below binds the *decoder* to {@link CascadeFields}; this binds
 * {@link CascadeFields} to the generated response. Without it the decoder could
 * drift into checking two fields the API no longer sends and keep compiling,
 * reporting every live response as unreadable. If `openapi/v1.yaml` drops
 * either field, this resolves to `never` and the assignment stops compiling.
 */
type GeneratedCarriesCascadeFields =
  CapabilityMatrixResponse extends CascadeFields ? true : never
export const CASCADE_FIELDS_ARE_ON_THE_WIRE: GeneratedCarriesCascadeFields = true

const cascadeSchema = z.object({
  cascadeLoaded: z.boolean(),
  policies: z.array(z.unknown()),
}) satisfies z.ZodType<CascadeFields>

/**
 * The first thing wrong with the body, as a short operator-facing phrase.
 *
 * Mirrors `features/scrub/schema.ts`: one issue, not a validation report, and a
 * joined path so a caller is told which field to take to whoever runs the
 * gateway.
 */
function firstFault(error: z.ZodError): string {
  const issue = error.issues[0]
  if (!issue) return 'the body could not be read'
  const path = issue.path.join('.')
  return path === '' ? issue.message : `${path}: ${issue.message}`
}

/**
 * Decode the cascade evidence, or say why it could not be read.
 *
 * Total, per the {@link Decoder} contract — a decoder that throws re-creates the
 * unmount the mechanism exists to prevent, one stack frame further in.
 */
export const decodeCascadeFields: Decoder<CascadeFields> = (body: unknown) => {
  const parsed = cascadeSchema.safeParse(body)
  if (parsed.success) return conforms(parsed.data)
  return violates(
    `The capability matrix came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so nothing about the policy cascade can be stated — including whether it is empty. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}

/**
 * The four collections the Capability *page* cannot function without.
 *
 * Wider than {@link CascadeFields} on purpose, and the departure from
 * "an absence no wider than the evidence for it" is deliberate — the two
 * decoders answer different questions:
 *
 *  - the cascade decoder answers *"how many policy documents are loaded"*,
 *    which stays determinable even if some unrelated field is malformed;
 *  - this one answers *"is this a capability matrix at all"*, and the page's
 *    honest answer is no unless all four are present. `agents` and `resources`
 *    are read at render (`applyFilters`, `sortAgents`, the tab counts); the
 *    other two are `.filter`ed by `CellInspectDrawer` the moment a cell is
 *    clicked. Requiring only the first two would move the same `TypeError` from
 *    page load to first interaction, which is a worse bug, not a narrower one.
 *
 * Elements are **not** inspected — only that each collection is a list. That is
 * the same accepted risk `api/capability.ts` documents for its `data as
 * CapabilityMatrix` cast, minus the part this closes: every field these rows
 * are read for is either rendered as an opaque display value or validated at
 * the point of use (`decisionMeta` / `decisionWeight` check membership in the
 * `Decision` union before indexing). What was missing, and what this adds, is
 * any check that the collections are collections.
 */
export interface MatrixShape {
  readonly agents: readonly unknown[]
  readonly resources: readonly unknown[]
  readonly policies: readonly unknown[]
  readonly sampleCalls: readonly unknown[]
}

/** A conforming matrix still carries all four collections under these names. */
type GeneratedCarriesMatrixShape = CapabilityMatrixResponse extends MatrixShape ? true : never
export const MATRIX_SHAPE_IS_ON_THE_WIRE: GeneratedCarriesMatrixShape = true

const matrixShapeSchema = z.object({
  agents: z.array(z.unknown()),
  resources: z.array(z.unknown()),
  policies: z.array(z.unknown()),
  sampleCalls: z.array(z.unknown()),
}) satisfies z.ZodType<MatrixShape>

/**
 * Decode the matrix the page renders, or say why it could not be read.
 *
 * Total, per the {@link Decoder} contract.
 */
export const decodeMatrixShape: Decoder<MatrixShape> = (body: unknown) => {
  const parsed = matrixShapeSchema.safeParse(body)
  if (parsed.success) return conforms(parsed.data)
  return violates(
    `The capability matrix came back in a shape this dashboard cannot read (${firstFault(parsed.error)}), so the grid cannot be rendered and nothing about any agent's capabilities can be stated. A proxy rewriting the response, a partial deploy, or a dashboard newer or older than the API all produce this.`,
  )
}
