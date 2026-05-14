import { z } from 'zod'

// Allowed enums — must stay in sync with `types.ts`. zod's enum-from-tuple
// pattern keeps the runtime validation aligned with the static types via
// the `satisfies` checks below.

const METRICS = ['budget_spent_pct', 'anomaly_score', 'approval_pending_age', 'policy_violation_count'] as const
const OPERATORS = ['>', '>=', '<', '='] as const
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const EVAL_WINDOWS = [300, 900, 3600] as const

const SUPPRESSION_KEY = /^[A-Za-z_][A-Za-z0-9_.-]*$/

/**
 * zod schema for the rule builder form. Threshold range is metric-aware:
 * percentage metrics (`budget_spent_pct`, `anomaly_score`) are clamped to
 * 0-100; the others accept any positive integer.
 */
export const ruleFormSchema = z
  .object({
    name: z.string().trim().min(1, 'name is required').max(128, 'name must be ≤ 128 chars'),
    description: z.string().trim().max(500, 'description must be ≤ 500 chars'),
    metric: z.enum(METRICS, { message: 'select a metric' }),
    operator: z.enum(OPERATORS, { message: 'select an operator' }),
    threshold: z
      .number({ message: 'threshold must be a number' })
      .finite('threshold must be a finite number'),
    evaluationWindowSeconds: z.union([z.literal(300), z.literal(900), z.literal(3600)]),
    severity: z.enum(SEVERITIES),
    destinationIds: z
      .array(z.string().min(1))
      .min(1, 'at least one destination is required'),
    dedupWindowSeconds: z
      .number({ message: 'dedup window must be a number' })
      .int('dedup window must be a whole minute')
      .min(0, 'dedup window cannot be negative'),
    suppressionLabels: z
      .array(
        z.object({
          key: z.string().regex(SUPPRESSION_KEY, 'key must match [A-Za-z_][A-Za-z0-9_.-]*'),
          value: z.string().min(1, 'value cannot be empty'),
        }),
      ),
    enabled: z.boolean(),
  })
  .superRefine((data, ctx) => {
    const isPercentage =
      data.metric === 'budget_spent_pct' || data.metric === 'anomaly_score'
    const max = isPercentage ? 100 : Number.MAX_SAFE_INTEGER
    if (data.threshold < 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['threshold'],
        message: 'threshold must be ≥ 0',
      })
    }
    if (data.threshold > max) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['threshold'],
        message: `threshold must be ≤ ${max} for metric ${data.metric}`,
      })
    }
  })

export type RuleFormValues = z.infer<typeof ruleFormSchema>

// Compile-time sanity: the literal arrays the schema relies on must match
// the unions exported from `types.ts`.
import type { AlertMetric, AlertOperator, Severity, EvaluationWindowSeconds } from './types'
const _metricCheck: readonly AlertMetric[] = METRICS satisfies readonly AlertMetric[]
const _operatorCheck: readonly AlertOperator[] = OPERATORS satisfies readonly AlertOperator[]
const _severityCheck: readonly Severity[] = SEVERITIES satisfies readonly Severity[]
const _windowCheck: readonly EvaluationWindowSeconds[] = EVAL_WINDOWS satisfies readonly EvaluationWindowSeconds[]
void [_metricCheck, _operatorCheck, _severityCheck, _windowCheck]
