import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConditionList } from './ConditionList'

describe('ConditionList', () => {
  it('renders one select per condition with the matching preset selected', () => {
    render(
      <ConditionList
        value={['always', 'host in allowlist']}
        onChange={() => {}}
      />,
    )
    expect(screen.getByTestId('editor-condition-select-0')).toHaveValue('always')
    expect(screen.getByTestId('editor-condition-select-1')).toHaveValue('host in allowlist')
  })

  it('renders "AND" between consecutive condition rows but not before the first', () => {
    render(
      <ConditionList
        value={['always', 'host in allowlist', 'amount < $100']}
        onChange={() => {}}
      />,
    )
    const ands = screen.getAllByText('AND')
    expect(ands).toHaveLength(2)
  })

  it('selecting a different preset calls onChange with the updated list', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<ConditionList value={['always']} onChange={onChange} />)
    await user.selectOptions(
      screen.getByTestId('editor-condition-select-0'),
      'host in allowlist',
    )
    expect(onChange).toHaveBeenCalledWith(['host in allowlist'])
  })

  it('"+ add condition" appends "always" to the list', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<ConditionList value={['amount < $100']} onChange={onChange} />)
    await user.click(screen.getByTestId('editor-condition-add'))
    expect(onChange).toHaveBeenCalledWith(['amount < $100', 'always'])
  })

  it('remove button drops the condition at the given index', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <ConditionList
        value={['always', 'host in allowlist', 'amount < $100']}
        onChange={onChange}
      />,
    )
    await user.click(screen.getByTestId('editor-condition-remove-1'))
    expect(onChange).toHaveBeenCalledWith(['always', 'amount < $100'])
  })
})
