import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FormProvider, useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import type { ReactNode } from 'react'
import { DedupAndSuppressionFields } from './DedupAndSuppressionFields'
import { ruleFormSchema, type RuleFormValues } from './ruleFormSchema'

const BASE_VALUES: RuleFormValues = {
  name: 'rule',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 50,
  evaluationWindowSeconds: 300,
  severity: 'HIGH',
  destinationIds: ['d1'],
  dedupWindowSeconds: 60,
  suppressionLabels: [],
  enabled: true,
}

function Harness({
  defaults = {},
  children,
}: {
  defaults?: Partial<RuleFormValues>
  children?: ReactNode
}) {
  const methods = useForm<RuleFormValues>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: { ...BASE_VALUES, ...defaults },
    mode: 'onChange',
  })
  return (
    <FormProvider {...methods}>
      <form>
        <DedupAndSuppressionFields />
        {children}
        <button type="button" data-testid="validate" onClick={() => methods.trigger()}>
          validate
        </button>
      </form>
    </FormProvider>
  )
}

describe('DedupAndSuppressionFields', () => {
  it('shows the empty-state hint when there are no suppression labels', () => {
    render(<Harness />)
    expect(screen.getByTestId('rule-dedup-suppression')).toBeInTheDocument()
    expect(
      screen.getByText(/No suppression labels — the rule will fire regardless/i),
    ).toBeInTheDocument()
    expect(screen.queryByTestId('rule-suppression-row-0')).not.toBeInTheDocument()
  })

  it('appends a new suppression label row on Add', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByTestId('rule-suppression-add'))
    expect(screen.getByTestId('rule-suppression-row-0')).toBeInTheDocument()
    expect(screen.getByTestId('rule-suppression-key-0')).toBeInTheDocument()
    expect(screen.getByTestId('rule-suppression-value-0')).toBeInTheDocument()
  })

  it('renders pre-seeded rows and removes a row on the remove button', async () => {
    const user = userEvent.setup()
    render(<Harness defaults={{ suppressionLabels: [{ key: 'env', value: 'prod' }] }} />)
    expect(screen.getByTestId('rule-suppression-key-0')).toHaveValue('env')
    expect(screen.getByTestId('rule-suppression-value-0')).toHaveValue('prod')

    await user.click(screen.getByTestId('rule-suppression-remove-0'))
    expect(screen.queryByTestId('rule-suppression-row-0')).not.toBeInTheDocument()
  })

  it('surfaces validation errors for an invalid suppression key and empty value', async () => {
    const user = userEvent.setup()
    render(<Harness defaults={{ suppressionLabels: [{ key: '1bad', value: '' }] }} />)

    await act(async () => {
      await user.click(screen.getByTestId('validate'))
    })

    expect(await screen.findByText(/key must match/i)).toBeInTheDocument()
    expect(screen.getByText(/value cannot be empty/i)).toBeInTheDocument()
  })

  it('surfaces a dedup-window validation error for a negative value', async () => {
    const user = userEvent.setup()
    render(<Harness defaults={{ dedupWindowSeconds: -5 }} />)

    await act(async () => {
      await user.click(screen.getByTestId('validate'))
    })

    expect(await screen.findByText(/dedup window cannot be negative/i)).toBeInTheDocument()
  })
})
