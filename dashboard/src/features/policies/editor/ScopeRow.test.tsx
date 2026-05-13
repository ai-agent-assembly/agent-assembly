import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ScopeRow } from './ScopeRow'

describe('ScopeRow', () => {
  it('renders the current scope value in the input', () => {
    render(<ScopeRow scope="research-bot-04" onScopeChange={() => {}} />)
    expect(screen.getByTestId('editor-scope-input')).toHaveValue('research-bot-04')
  })

  it('fires onScopeChange on each input keystroke', async () => {
    const user = userEvent.setup()
    const onScopeChange = vi.fn()
    render(<ScopeRow scope="" onScopeChange={onScopeChange} />)
    await user.type(screen.getByTestId('editor-scope-input'), 'abc')
    expect(onScopeChange).toHaveBeenCalledTimes(3)
    expect(onScopeChange).toHaveBeenLastCalledWith('c')
  })

  it('renders the prod and staging env tags', () => {
    render(<ScopeRow scope="global" onScopeChange={() => {}} />)
    expect(screen.getByTestId('editor-scope-env-prod')).toBeInTheDocument()
    expect(screen.getByTestId('editor-scope-env-staging')).toBeInTheDocument()
  })
})
