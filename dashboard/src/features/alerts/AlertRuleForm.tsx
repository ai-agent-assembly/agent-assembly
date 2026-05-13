import { useEffect } from 'react'
import { FormProvider, useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { ConditionBuilder } from './ConditionBuilder'
import { SeveritySelect } from './SeveritySelect'
import { DestinationsPicker } from './DestinationsPicker'
import { DedupAndSuppressionFields } from './DedupAndSuppressionFields'
import { useCreateAlertRuleMutation, useUpdateAlertRuleMutation } from './api'
import { ruleFormSchema, type RuleFormValues } from './ruleFormSchema'
import { useToast } from '../../components/Toast'
import type { AlertRule, AlertRuleInput } from './types'

interface AlertRuleFormProps {
  open: boolean
  onClose: () => void
  /** When present, the form is in edit mode; otherwise it creates a new rule. */
  initialValue?: AlertRule
  /** Optional callback fired after a successful save (mutation resolves). */
  onSaved?: (rule: AlertRule) => void
}

function defaultValues(initial: AlertRule | undefined): RuleFormValues {
  if (initial) {
    return {
      name: initial.name,
      description: initial.description,
      metric: initial.metric,
      operator: initial.operator,
      threshold: initial.threshold,
      evaluationWindowSeconds: initial.evaluationWindowSeconds,
      severity: initial.severity,
      destinationIds: [...initial.destinationIds],
      dedupWindowSeconds: initial.dedupWindowSeconds,
      suppressionLabels: Object.entries(initial.suppressionLabels).map(([key, value]) => ({
        key,
        value,
      })),
      enabled: initial.enabled,
    }
  }
  return {
    name: '',
    description: '',
    metric: 'budget_spent_pct',
    operator: '>',
    threshold: 90,
    evaluationWindowSeconds: 300,
    severity: 'CRITICAL',
    destinationIds: [],
    dedupWindowSeconds: 600,
    suppressionLabels: [],
    enabled: true,
  }
}

function toRuleInput(values: RuleFormValues): AlertRuleInput {
  return {
    name: values.name.trim(),
    description: values.description.trim(),
    metric: values.metric,
    operator: values.operator,
    threshold: values.threshold,
    evaluationWindowSeconds: values.evaluationWindowSeconds,
    severity: values.severity,
    destinationIds: values.destinationIds,
    dedupWindowSeconds: values.dedupWindowSeconds,
    suppressionLabels: Object.fromEntries(
      values.suppressionLabels.map((l) => [l.key, l.value]),
    ),
    enabled: values.enabled,
  }
}

export function AlertRuleForm({
  open,
  onClose,
  initialValue,
  onSaved,
}: AlertRuleFormProps) {
  const methods = useForm<RuleFormValues>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: defaultValues(initialValue),
    mode: 'onSubmit',
  })

  // Reset when opening for a different rule.
  useEffect(() => {
    if (open) methods.reset(defaultValues(initialValue))
  }, [open, initialValue, methods])

  const create = useCreateAlertRuleMutation()
  const update = useUpdateAlertRuleMutation()
  const { toast } = useToast()

  const submitting = create.isPending || update.isPending

  const handleSubmit = methods.handleSubmit(async (values) => {
    const input = toRuleInput(values)
    try {
      const saved = initialValue
        ? await update.mutateAsync({ id: initialValue.id, input })
        : await create.mutateAsync(input)
      toast(initialValue ? `Updated rule "${saved.name}"` : `Created rule "${saved.name}"`, 'success')
      onSaved?.(saved)
      onClose()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save rule'
      toast(message, 'error')
    }
  })

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="alert-rule-form-title"
      data-testid="alert-rule-form"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.4)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '2rem',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        style={{
          width: 'min(720px, 100%)',
          background: '#fff',
          borderRadius: '8px',
          boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
          padding: '1.25rem',
          maxHeight: '90vh',
          overflow: 'auto',
        }}
      >
        <header
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1rem',
          }}
        >
          <h2 id="alert-rule-form-title" style={{ fontSize: '1.125rem', margin: 0 }}>
            {initialValue ? 'Edit alert rule' : 'New alert rule'}
          </h2>
          <button
            type="button"
            data-testid="alert-rule-form-close"
            aria-label="Close"
            onClick={onClose}
            style={{
              border: 'none',
              background: 'transparent',
              fontSize: '1.25rem',
              cursor: 'pointer',
              color: '#6b7280',
            }}
          >
            ✕
          </button>
        </header>

        <FormProvider {...methods}>
          <form
            onSubmit={handleSubmit}
            style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}
          >
            <label
              style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.875rem' }}
            >
              <span>Name</span>
              <input
                id="rule-name"
                data-testid="rule-name"
                {...methods.register('name')}
              />
              {methods.formState.errors.name && (
                <span style={{ color: '#dc2626', fontSize: '0.75rem' }}>
                  {methods.formState.errors.name.message}
                </span>
              )}
            </label>

            <label
              style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.875rem' }}
            >
              <span>Description (optional)</span>
              <textarea
                id="rule-description"
                data-testid="rule-description"
                rows={2}
                {...methods.register('description')}
              />
            </label>

            <ConditionBuilder />
            <SeveritySelect />
            <DestinationsPicker />
            <DedupAndSuppressionFields />

            <label
              style={{ display: 'inline-flex', gap: '0.5rem', alignItems: 'center', fontSize: '0.875rem' }}
            >
              <input
                type="checkbox"
                data-testid="rule-enabled"
                {...methods.register('enabled')}
              />
              Enabled
            </label>

            <footer
              style={{
                display: 'flex',
                gap: '0.5rem',
                justifyContent: 'flex-end',
                marginTop: '0.5rem',
              }}
            >
              <button
                type="button"
                data-testid="alert-rule-form-cancel"
                onClick={onClose}
                disabled={submitting}
                style={{ padding: '6px 14px' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                data-testid="alert-rule-form-submit"
                disabled={submitting}
                style={{
                  padding: '6px 14px',
                  background: '#1f2937',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: submitting ? 'wait' : 'pointer',
                }}
              >
                {submitting ? 'Saving…' : initialValue ? 'Save changes' : 'Create rule'}
              </button>
            </footer>
          </form>
        </FormProvider>
      </div>
    </div>
  )
}
