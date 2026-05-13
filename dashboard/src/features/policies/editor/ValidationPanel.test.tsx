import { render, screen } from '@testing-library/react'
import { ValidationPanel } from './ValidationPanel'
import type { ValidationIssue } from './types'

describe('ValidationPanel', () => {
  it('shows the success row when there are no issues', () => {
    render(<ValidationPanel issues={[]} />)
    expect(screen.getByTestId('editor-validation-ok')).toHaveTextContent(/ready to simulate/)
    expect(screen.getByTestId('editor-validation-error-count')).toHaveTextContent('0 errors')
    expect(screen.getByTestId('editor-validation-warn-count')).toHaveTextContent('0 warnings')
  })

  it('counts errors and warnings separately in the header chips', () => {
    const issues: ValidationIssue[] = [
      { severity: 'error', rule: 'R1', message: 'Select at least one verb.' },
      { severity: 'warn', rule: 'R1', message: 'No conditions — rule applies universally.' },
      { severity: 'error', rule: '—', message: 'Policy name is required.' },
    ]
    render(<ValidationPanel issues={issues} />)
    expect(screen.getByTestId('editor-validation-error-count')).toHaveTextContent('2 errors')
    expect(screen.getByTestId('editor-validation-warn-count')).toHaveTextContent('1 warnings')
  })

  it('renders one row per issue, preserving order and showing the rule label', () => {
    const issues: ValidationIssue[] = [
      { severity: 'error', rule: '—', message: 'Policy name is required.' },
      { severity: 'warn', rule: 'R2', message: 'No conditions — rule applies universally.' },
    ]
    render(<ValidationPanel issues={issues} />)
    expect(screen.getByTestId('editor-validation-row-0')).toHaveTextContent('Policy name is required.')
    expect(screen.getByTestId('editor-validation-row-1')).toHaveTextContent('R2')
    expect(screen.getByTestId('editor-validation-row-1')).toHaveTextContent(
      'No conditions — rule applies universally.',
    )
  })

  it('hides the success row when issues are present', () => {
    const issues: ValidationIssue[] = [
      { severity: 'error', rule: 'R1', message: 'Verb missing.' },
    ]
    render(<ValidationPanel issues={issues} />)
    expect(screen.queryByTestId('editor-validation-ok')).not.toBeInTheDocument()
  })
})
