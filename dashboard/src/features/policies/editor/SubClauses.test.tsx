import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SubClauses } from './SubClauses'
import { defaultRule } from './constants'
import type { RuleDraft } from './types'

function ruleWith(patch: Partial<RuleDraft>): RuleDraft {
  return { ...defaultRule(), ...patch }
}

describe('SubClauses — render gating per action', () => {
  it('renders nothing when action is "allow"', () => {
    render(<SubClauses ruleIndex={0} rule={ruleWith({ action: 'allow' })} onChange={() => {}} />)
    expect(screen.queryByTestId('editor-narrow')).not.toBeInTheDocument()
    expect(screen.queryByTestId('editor-approver')).not.toBeInTheDocument()
    expect(screen.queryByTestId('editor-scrub')).not.toBeInTheDocument()
    expect(screen.queryByTestId('editor-except')).not.toBeInTheDocument()
  })

  it('narrow shows the narrow paths sub-clause and the except list', () => {
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({ action: 'narrow', narrowPaths: ['s3://foo'] })}
        onChange={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-narrow')).toBeInTheDocument()
    expect(screen.getByTestId('editor-except')).toBeInTheDocument()
  })

  it('approval shows the three approver popovers and the except list', () => {
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({
          action: 'approval',
          approver: { who: 'security-oncall', nOfM: '1-of-1', sla: '30m' },
        })}
        onChange={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-approver-who')).toBeInTheDocument()
    expect(screen.getByTestId('editor-approver-quorum')).toBeInTheDocument()
    expect(screen.getByTestId('editor-approver-sla')).toBeInTheDocument()
    expect(screen.getByTestId('editor-except')).toBeInTheDocument()
  })

  it('scrub-then-allow shows scrub tag toggles plus the except list', () => {
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({ action: 'scrub-then-allow', scrubFields: ['emails'] })}
        onChange={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-scrub')).toBeInTheDocument()
    expect(screen.getByTestId('editor-scrub-emails')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('editor-scrub-SSN')).toHaveAttribute('aria-pressed', 'false')
  })

  it('deny shows only the except list', () => {
    render(
      <SubClauses ruleIndex={0} rule={ruleWith({ action: 'deny' })} onChange={() => {}} />,
    )
    expect(screen.getByTestId('editor-except')).toBeInTheDocument()
    expect(screen.queryByTestId('editor-narrow')).not.toBeInTheDocument()
  })
})

describe('SubClauses — narrow paths', () => {
  it('typing + add appends a new path through onChange', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({ action: 'narrow', narrowPaths: ['s3://foo'] })}
        onChange={onChange}
      />,
    )
    await user.type(screen.getByTestId('editor-narrow-paths-input'), 's3://bar')
    await user.click(screen.getByTestId('editor-narrow-paths-add'))
    expect(onChange).toHaveBeenCalledWith({ narrowPaths: ['s3://foo', 's3://bar'] })
  })

  it('remove button drops the chip at that index', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({ action: 'narrow', narrowPaths: ['s3://foo', 's3://bar'] })}
        onChange={onChange}
      />,
    )
    await user.click(screen.getByTestId('editor-narrow-paths-remove-0'))
    expect(onChange).toHaveBeenCalledWith({ narrowPaths: ['s3://bar'] })
  })
})

describe('SubClauses — approver', () => {
  it('changing the who select fires onChange with the patched approver', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({
          action: 'approval',
          approver: { who: 'security-oncall', nOfM: '1-of-1', sla: '30m' },
        })}
        onChange={onChange}
      />,
    )
    await user.selectOptions(screen.getByTestId('editor-approver-who'), 'finance-head')
    expect(onChange).toHaveBeenCalledWith({
      approver: { who: 'finance-head', nOfM: '1-of-1', sla: '30m' },
    })
  })
})

describe('SubClauses — scrub', () => {
  it('toggling a preset adds it when off and removes when on', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({ action: 'scrub-then-allow', scrubFields: ['emails'] })}
        onChange={onChange}
      />,
    )
    await user.click(screen.getByTestId('editor-scrub-SSN'))
    expect(onChange).toHaveBeenLastCalledWith({ scrubFields: ['emails', 'SSN'] })
    await user.click(screen.getByTestId('editor-scrub-emails'))
    expect(onChange).toHaveBeenLastCalledWith({ scrubFields: [] })
  })
})

describe('SubClauses — except', () => {
  it('shows the no-exceptions help text when the list is empty', () => {
    render(
      <SubClauses ruleIndex={0} rule={ruleWith({ action: 'deny' })} onChange={() => {}} />,
    )
    expect(screen.getByText(/No exceptions/)).toBeInTheDocument()
  })

  it('shows the count help text when non-empty', () => {
    render(
      <SubClauses
        ruleIndex={0}
        rule={ruleWith({ action: 'deny', exceptions: ['ops@', 'leads@'] })}
        onChange={() => {}}
      />,
    )
    expect(screen.getByText(/2 call\(s\)/)).toBeInTheDocument()
  })
})
