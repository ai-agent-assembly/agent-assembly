import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuleCard } from './RuleCard'
import { defaultRule } from './constants'
import type { RuleDraft } from './types'

function ruleWith(patch: Partial<RuleDraft> = {}): RuleDraft {
  return { ...defaultRule(), ...patch }
}

describe('RuleCard', () => {
  it('renders the rule number "R{index+1}"', () => {
    render(
      <RuleCard
        index={2}
        rule={ruleWith()}
        onChange={() => {}}
        onDuplicate={() => {}}
        onRemove={() => {}}
      />,
    )
    expect(screen.getByText('R3')).toBeInTheDocument()
  })

  it('changing the resource select fires onChange with { resource }', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <RuleCard
        index={0}
        rule={ruleWith()}
        onChange={onChange}
        onDuplicate={() => {}}
        onRemove={() => {}}
      />,
    )
    await user.selectOptions(screen.getByTestId('editor-rule-0-resource'), 's3')
    expect(onChange).toHaveBeenCalledWith({ resource: 's3' })
  })

  it('clicking a verb toggle flips its membership in rule.verb', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <RuleCard
        index={0}
        rule={ruleWith({ verb: ['read'] })}
        onChange={onChange}
        onDuplicate={() => {}}
        onRemove={() => {}}
      />,
    )
    await user.click(screen.getByTestId('editor-rule-0-verb-write'))
    expect(onChange).toHaveBeenCalledWith({ verb: ['read', 'write'] })
  })

  it('changing the action seeds narrowPaths from defaults when switching to narrow', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <RuleCard
        index={0}
        rule={ruleWith({ resource: 's3', action: 'allow' })}
        onChange={onChange}
        onDuplicate={() => {}}
        onRemove={() => {}}
      />,
    )
    await user.click(screen.getByTestId('editor-action-narrow'))
    expect(onChange).toHaveBeenCalledWith({
      action: 'narrow',
      narrowPaths: ['s3://reports/*'],
    })
  })

  it('switching from narrow to another action does not seed paths a second time', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <RuleCard
        index={0}
        rule={ruleWith({ action: 'narrow', narrowPaths: ['s3://existing'] })}
        onChange={onChange}
        onDuplicate={() => {}}
        onRemove={() => {}}
      />,
    )
    await user.click(screen.getByTestId('editor-action-allow'))
    expect(onChange).toHaveBeenCalledWith({ action: 'allow' })
  })

  it('duplicate and remove buttons fire their callbacks', async () => {
    const user = userEvent.setup()
    const onDuplicate = vi.fn()
    const onRemove = vi.fn()
    render(
      <RuleCard
        index={0}
        rule={ruleWith()}
        onChange={() => {}}
        onDuplicate={onDuplicate}
        onRemove={onRemove}
      />,
    )
    await user.click(screen.getByTestId('editor-rule-0-duplicate'))
    expect(onDuplicate).toHaveBeenCalledTimes(1)
    await user.click(screen.getByTestId('editor-rule-0-remove'))
    expect(onRemove).toHaveBeenCalledTimes(1)
  })

  it('composes ConditionList, ActionPicker, SubClauses, and WindowSeverityRow', () => {
    render(
      <RuleCard
        index={0}
        rule={ruleWith({ action: 'approval' })}
        onChange={() => {}}
        onDuplicate={() => {}}
        onRemove={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-conditions')).toBeInTheDocument()
    expect(screen.getByTestId('editor-action-picker')).toBeInTheDocument()
    expect(screen.getByTestId('editor-approver')).toBeInTheDocument()
    expect(screen.getByTestId('editor-window-severity')).toBeInTheDocument()
  })
})
